// 패턴을 이 파일의 상수로 옮겼습니다. 외부 정보 없이 경보 하나로 계산합니다.
const GROUP_PATTERN = {
  name: '관리자 그룹의 의심스러운 추가·재등록',
  condition: 'administrators 그룹 변경과 원격 추가·일반 계정의 추가 직후 명령·동일 주소 여러 계정 추가·제거 직후 재등록을 결합한다.',
  evidence: 'MITRE T1078: 정상 계정 악용의 점검 신호이며 그룹 변경 하나로 도용을 확정하지 않는다.',
  added: /관리자\s*그룹에\s*(?:추가|들어가)|관리자\s*그룹\s*추가/u,
  remote: /원격\s*주소/u,
  ordinary: /평범한\s*계정/u,
  immediate: /곧바로/u,
  multiple: /같은\s*주소에서\s*계정\s*\d+개/u,
  readded: /관리자\s*그룹에서\s*빠진.*\d+분\s*뒤.*다시\s*관리자로\s*들어/u,
};
const COMMAND_PATTERN = {
  name: '낯선 관리자 명령·세션 권한 전환',
  condition: '새 관리자 명령·낯선 주소의 세션 전환·다른 계정 권한의 관리자 명령을 확인하며 취소·실패·명령 부재는 알림에만 남긴다.',
  evidence: 'MITRE T1068·T1078: 권한 상승과 계정 악용 점검이며 취약점 증거 없는 T1068 성립은 미확인이다.',
  executed: /(?:관리자|권한)\s*명령을\s*실행|명령\s*실행/u,
  newAdmin: /방금\s*관리자가\s*된/u,
  session: /세션이\s*관리자\s*권한으로\s*바뀌/u,
  unseen: /처음\s*보는\s*주소|주소는\s*처음\s*봅니다/u,
  borrowed: /다른\s*계정의\s*권한/u,
};
const HOURS_PATTERN = {
  name: '업무 시간 밖의 복합 권한 사용',
  condition: '경보의 업무 시간 밖 표기와 명령 실행에 낯선 주소 또는 관리자 그룹 추가가 함께 있는지 확인한다.',
  evidence: 'MITRE T1078: 평소와 다른 계정 사용 점검의 보조 신호이며 업무 시간표를 임의로 만들지 않는다.',
  unusual: /수업\s*시간\s*밖|업무처럼\s*보이지\s*않는\s*시각/u,
};
const NO_PATTERN = '근거 패턴 없음';
const HIGH_RULE_LEVEL = 10; // 수업용 기준입니다.
const MAX_TEXT = 4096;

function bounded(value) {
  return typeof value === 'string' && value.length <= MAX_TEXT
    && !/[\u0000-\u001f\u007f-\u009f]/u.test(value) ? value : '';
}

function validSource(value) {
  if (typeof value !== 'string' || !/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(value)) return false;
  return value.split('.').every(part => Number(part) <= 255 && String(Number(part)) === part);
}

function result(confidence, reason) {
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason };
}

export function decide(alert) {
  const description = bounded(alert?.rule?.description);
  const group = bounded(alert?.data?.group).toLowerCase();
  const level = Number.isInteger(alert?.rule?.level) && alert.rule.level >= 0
    && alert.rule.level <= 16 ? alert.rule.level : 0;
  const value = alert?.data?.count;
  const count = Number.isSafeInteger(value) && value >= 0 ? value
    : typeof value === 'string' && /^\d{1,6}$/u.test(value) ? Number(value) : 0;
  // 실패·취소·변경 부재를 공격 성공으로 읽지 않습니다.
  const incomplete = /취소|실패|명령은\s*없|변경은\s*없|관리자\s*그룹은\s*아닙니다|추가되지|실행하지|바뀌지/u.test(description);
  const executed = COMMAND_PATTERN.executed.test(description);
  const added = group === 'administrators' && GROUP_PATTERN.added.test(description);
  const groupEvidence = group === 'administrators' && (
    added && (GROUP_PATTERN.remote.test(description)
      || GROUP_PATTERN.ordinary.test(description) && GROUP_PATTERN.immediate.test(description) && executed
      || GROUP_PATTERN.multiple.test(description) && count >= 3)
    || GROUP_PATTERN.readded.test(description) && count >= 2
  );
  const commandEvidence = executed && (COMMAND_PATTERN.newAdmin.test(description)
    || COMMAND_PATTERN.borrowed.test(description))
    || COMMAND_PATTERN.session.test(description) && COMMAND_PATTERN.unseen.test(description);
  const hoursEvidence = HOURS_PATTERN.unusual.test(description) && executed
    && (COMMAND_PATTERN.unseen.test(description) || added);
  const strong = hoursEvidence ? HOURS_PATTERN.name
    : groupEvidence ? GROUP_PATTERN.name : commandEvidence ? COMMAND_PATTERN.name : null;
  if (strong && !incomplete) {
    return result(level >= HIGH_RULE_LEVEL && validSource(alert?.data?.srcip) ? 0.95 : 0.75, strong);
  }
  // 정상 로그인·읽기·예약 작업은 규칙 수준 하나로 차단하지 않습니다.
  const normal = /로그인했습니다|로그아웃|소속을\s*읽기만|비밀번호를\s*변경|자기\s*세션\s*정보를\s*조회|자료실을\s*열|평소\s*예약\s*작업을\s*확인/u.test(description);
  if (normal && !/관리자\s*그룹|권한으로\s*바뀌|명령/u.test(description)) return result(0.1, NO_PATTERN);
  if (HOURS_PATTERN.unusual.test(description) && /권한|관리자/u.test(description)) return result(0.6, HOURS_PATTERN.name);
  if (/관리자\s*명령|권한\s*(?:상승|명령)|관리자\s*권한|관리자가/u.test(description)) return result(0.6, COMMAND_PATTERN.name);
  if (/그룹|계정\s*종류/u.test(description)) return result(0.6, GROUP_PATTERN.name);
  return result(0.1, NO_PATTERN);
}
