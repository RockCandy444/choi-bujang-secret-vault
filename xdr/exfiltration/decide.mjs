// 네 패턴을 상수로 옮겼습니다. 외부 정보 없이 경보 하나로 계산합니다.
const DESTINATION_PATTERN = {
  name: '처음 보는 목적지로 대용량 전송',
  condition: '낯선 목적지·완료된 전송·50000000 bytes 이상을 결합한다.',
  evidence: 'MITRE T1041·T1048의 반출 점검 신호이며 통로·프로토콜은 미확인이다.',
  unseen: /처음\s*보는\s*(?:목적지|주소)|목적지는\s*처음\s*봅니다|평소와\s*다른\s*주소/u,
};
const ARCHIVE_PATTERN = {
  name: '업무 시간 밖 압축 파일 반출',
  condition: '시간 밖 표기·압축 파일·완료된 대용량 전송을 결합한다.',
  evidence: 'MITRE T1048의 파일 반출 점검이며 시간·압축만으로 확정하지 않는다.',
  archive: /압축\s*파일/u,
  offHours: /(?:업무|수업)\s*시간\s*밖/u,
};
const REPEAT_PATTERN = {
  name: '같은 목적지의 반복 대용량·전체 자료 반출',
  condition: '같은 목적지로 대용량 반복 5회 이상 또는 짧은 시간의 전체 외부 복사 100건 이상을 확인한다.',
  evidence: 'MITRE T1041의 반출 점검이며 명령 통로가 없으면 기법 성립은 미확인이다.',
  sameDestination: /같은\s*목적지/u,
  repeated: /반복|전송이\s*\d+번/u,
  completeCopy: /짧은\s*시간.*자료실\s*전체.*외부\s*주소.*복사됐/u,
  channel: /명령\s*통로/u,
};
const PORT_PATTERN = {
  name: '평소와 다른 포트의 연속 자료 반출',
  condition: '평소와 다른 포트·연속 자료 전송·대용량·20건 이상을 확인한다.',
  evidence: 'MITRE T1048의 반출 점검이며 포트 하나로 프로토콜을 확정하지 않는다.',
  unusualPort: /평소에\s*쓰지\s*않던\s*포트/u,
  continuous: /자료.*연속\s*전송/u,
};
const NO_PATTERN = '근거 패턴 없음';
const LARGE_BYTES = 50000000;
const HIGH_RULE_LEVEL = 10; // 아래 수치는 가상 경보의 로컬 기준입니다.

function text(value) {
  return typeof value === 'string' && value.length <= 4096
    && !/[\u0000-\u001f\u007f]/u.test(value) ? value : '';
}

function number(value) {
  if (typeof value === 'string' && /^\d{1,15}$/u.test(value)) value = Number(value);
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function ipv4(value) {
  return typeof value === 'string' && /^(?:\d{1,3}\.){3}\d{1,3}$/u.test(value)
    && value.split('.').every(part => String(Number(part)) === part && Number(part) <= 255);
}

function result(confidence, reason) {
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason };
}

export function decide(alert) {
  const description = text(alert?.rule?.description);
  const bytes = number(alert?.data?.bytes);
  const files = number(alert?.data?.files);
  const count = number(alert?.data?.count);
  const level = Number.isInteger(alert?.rule?.level) && alert.rule.level >= 0
    && alert.rule.level <= 16 ? alert.rule.level : 0;
  const unseen = DESTINATION_PATTERN.unseen.test(description);
  const archive = ARCHIVE_PATTERN.archive.test(description);
  const offHours = ARCHIVE_PATTERN.offHours.test(description);
  const channel = REPEAT_PATTERN.channel.test(description);
  const unusualPort = PORT_PATTERN.unusualPort.test(description);
  const repeated = REPEAT_PATTERN.sameDestination.test(description)
    && REPEAT_PATTERN.repeated.test(description);
  const completeCopy = REPEAT_PATTERN.completeCopy.test(description);
  const volumeSignal = /대용량|전송량이\s*평소보다|파일\s*수가.*늘|자료\s*\d+건.*한\s*번에\s*읽/u.test(description);
  const partial = /백업처럼\s*보이는\s*전송|일부만\s*다른\s*주소/u.test(description);
  const reason = archive && offHours ? ARCHIVE_PATTERN.name
    : unusualPort ? PORT_PATTERN.name : repeated || completeCopy || channel || volumeSignal
      ? REPEAT_PATTERN.name : archive ? ARCHIVE_PATTERN.name : unseen || partial ? DESTINATION_PATTERN.name : NO_PATTERN;
  const risk = unseen || archive || offHours || channel || unusualPort || repeated || completeCopy || volumeSignal || partial;
  // 부재·실패·취소는 전송 완료로 취급하지 않습니다.
  const incomplete = /실패|취소|(?:외부\s*전송|파일\s*전송|전송)은?\s*(?:아직\s*)?없|큰\s*파일은\s*아닙니다/u.test(description);
  if (incomplete) return result(risk ? 0.6 : 0.1, risk ? reason : NO_PATTERN);
  const transferred = /나갔|올라갔|전송됐|연속\s*전송|전송이\s*\d+번|복사됐/u.test(description);
  const large = bytes !== null && bytes >= LARGE_BYTES;
  const destinationEvidence = unseen && large && transferred;
  const archiveEvidence = archive && offHours && large && transferred;
  const repeatEvidence = large && transferred && (repeated && count !== null && count >= 5
    || completeCopy && bytes >= 100000000 && files !== null && files >= 100);
  const portEvidence = unusualPort && PORT_PATTERN.continuous.test(description)
    && large && files !== null && files >= 20;
  const strongReason = archiveEvidence ? ARCHIVE_PATTERN.name : portEvidence ? PORT_PATTERN.name
    : repeatEvidence ? REPEAT_PATTERN.name : destinationEvidence ? DESTINATION_PATTERN.name : null;
  // 수준·번호·계정·MITRE 표기만으로 차단하지 않습니다. 목적지 없는 경보는 알림입니다.
  if (strongReason) return result(level >= HIGH_RULE_LEVEL && ipv4(alert?.data?.dstip) ? 0.95 : 0.75, strongReason);
  return result(risk ? 0.6 : 0.1, risk ? reason : NO_PATTERN);
}
