// 로컬 읽기 도구입니다. 심판용 decide.mjs에서 불러오지 않습니다.
import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const FIXTURE_URL = new URL('../fixtures/brute-force.json', import.meta.url);
const REDACTED = '[가림]';
const SECRET_PATTERNS = [
  /(?:^|[^a-z0-9])(?:password|passwd|pwd|token|secret|authorization|bearer|api[_ -]?key|private[_ -]?key)(?=$|[^a-z0-9])/iu,
  /(?:비밀번호|암호|토큰|비밀키|개인키|서버\s*키)\s*["']?\s*[:=]/u,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/u,
  /\b(?:eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|sk[-_][A-Za-z0-9_-]+|gh[pousr]_[A-Za-z0-9_]+|AKIA[A-Z0-9]{16})\b/u,
  /[A-Za-z0-9_+\/-]{24,}/u,
  /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/iu,
  /https?:\/\/[^\s]+/iu,
];

function safeText(value, accepts = () => true) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || SECRET_PATTERNS.some(pattern => pattern.test(value))) {
    return REDACTED;
  }
  if (/[\u0000-\u001f\u007f-\u009f]/u.test(value) || !accepts(value)) return REDACTED;
  return value;
}

// 지정한 다섯 필드만 반환합니다. 누락된 값은 null, 의심스러운 값은 가립니다.
export function extractAlerts(fixture) {
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'brute-force' || !Array.isArray(fixture.alerts)) {
    throw new Error('무차별 로그인 경보 묶음 형식이 아닙니다.');
  }
  return Array.from(fixture.alerts, alert => ({
    timestamp: safeText(alert?.timestamp, value =>
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/u.test(value)
      && Number.isFinite(Date.parse(value))),
    srcip: safeText(alert?.data?.srcip, value => isIP(value) !== 0),
    // 수업용 가상 계정만 출력하여 실제 계정 식별자도 노출하지 않습니다.
    srcuser: safeText(alert?.data?.srcuser, value => /^user\d{2,}$/u.test(value)),
    level: Number.isInteger(alert?.rule?.level)
      && alert.rule.level >= 0 && alert.rule.level <= 16 ? alert.rule.level : null,
    description: safeText(alert?.rule?.description),
  }));
}

export async function readAlerts() {
  let fixture;
  try {
    fixture = JSON.parse(await readFile(FIXTURE_URL, 'utf8'));
  } catch {
    // JSON 파싱 오류 원문에는 경보 내용이 섞일 수 있으므로 출력하지 않습니다.
    throw new Error('경보 파일을 읽거나 JSON 형식을 해석하지 못했습니다.');
  }
  return extractAlerts(fixture);
}

const isMain = process.argv[1]
  && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    const rows = await readAlerts();
    // 표준 출력은 경보당 JSON 한 줄입니다. 건수 안내는 표준 오류로 분리합니다.
    for (const row of rows) process.stdout.write(`${JSON.stringify(row)}\n`);
    process.stderr.write(`경보 ${rows.length}건 / 추출 ${rows.length}줄\n`);
  } catch {
    process.stderr.write('경보 읽기 실패: 파일과 경보 묶음 형식을 확인하세요.\n');
    process.exitCode = 1;
  }
}
