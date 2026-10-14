// 패턴의 이름과 조건을 상수로 옮겼습니다. 이 파일만으로 계산합니다.
const SERVICE_PATTERN = {
  name: '서명 없는 서비스 생성·변경',
  topic: /서비스/u,
  unsigned: /서명\s*없는|서명이\s*없/u,
  changed: /새\s*서비스|서비스\s*등록|서비스\s*실행\s*파일이\s*바뀌/u,
  repeated: /연속/u,
  retained: /평소\s*목록에\s*없는\s*서비스.*다시\s*켜도\s*남.*등록/u,
};
const TASK_PATTERN = {
  name: '낯선 예약 작업과 임시 실행 경로',
  topic: /예약\s*작업/u,
  unusual: /처음\s*보는|임의\s*문자열|수업\s*시간\s*밖|같은\s*임시\s*파일.*함께/u,
};
const STARTUP_PATTERN = {
  name: '평소 목록 외 시작 폴더 추가',
  topic: /시작\s*(?:폴더|프로그램|항목)/u,
  added: /평소\s*목록에\s*없는\s*프로그램.*추가/u,
};
const NO_PATTERN = '근거 패턴 없음';
const MAX_TEXT = 4096;
const HIGH_RULE_LEVEL = 10; // 수업용 기준입니다.
const TEMP_EXECUTABLE = /\\(?:temp|tmp)\\[^\\]+\.(?:exe|com|cmd|bat|ps1)$/iu;
const STARTUP_EXECUTABLE = /\\start menu\\programs\\startup\\[^\\]+\.(?:exe|com|cmd|bat|ps1|lnk)$/iu;

function bounded(value) {
  return typeof value === 'string' && value.length <= MAX_TEXT
    && !/[\u0000-\u001f\u007f]/u.test(value) ? value : '';
}

function result(confidence, reason) {
  return {
    action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence,
    reason,
  };
}

export function decide(alert) {
  const description = bounded(alert?.rule?.description);
  const path = bounded(alert?.data?.path).replace(/\\+/gu, '\\');
  const level = Number.isInteger(alert?.rule?.level) && alert.rule.level >= 0
    && alert.rule.level <= 16 ? alert.rule.level : 0;
  const service = SERVICE_PATTERN.topic.test(description);
  const task = TASK_PATTERN.topic.test(description);
  const startup = STARTUP_PATTERN.topic.test(description);
  const temp = TEMP_EXECUTABLE.test(path);
  const count = alert?.data?.count;
  const repeated = (Number.isSafeInteger(count) && count >= 3)
    || (typeof count === 'string' && /^\d{1,6}$/u.test(count) && Number(count) >= 3);

  const serviceEvidence = service && (
    SERVICE_PATTERN.unsigned.test(description) && SERVICE_PATTERN.changed.test(description)
      && (temp || SERVICE_PATTERN.repeated.test(description) && repeated)
    || SERVICE_PATTERN.retained.test(description) && temp
  );
  const taskEvidence = task && temp && TASK_PATTERN.unusual.test(description);
  const startupEvidence = startup && STARTUP_EXECUTABLE.test(path)
    && STARTUP_PATTERN.added.test(description);
  const strongPattern = serviceEvidence ? SERVICE_PATTERN.name
    : taskEvidence ? TASK_PATTERN.name : startupEvidence ? STARTUP_PATTERN.name : null;
  if (strongPattern) return result(level >= HIGH_RULE_LEVEL ? 0.95 : 0.75, strongPattern);

  // 평소 작업·서명된 기존 서비스·목록 읽기는 높은 수준 하나로 차단하지 않습니다.
  const unchanged = /평소\s*시각에\s*그대로|기존\s*수업\s*도구\s*서비스가\s*서명된|목록을\s*읽기만|기존\s*예약\s*작업.*마쳤/u.test(description);
  if (unchanged) return result(0.1, NO_PATTERN);
  if (task) return result(0.6, TASK_PATTERN.name);
  if (startup) return result(0.6, STARTUP_PATTERN.name);
  if (service || temp && /실행\s*파일/u.test(description)) return result(0.6, SERVICE_PATTERN.name);
  return result(0.1, NO_PATTERN);
}
