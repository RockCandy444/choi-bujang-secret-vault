// patterns.json의 세 패턴 이름을 상수로 옮겨 이 파일만으로 계산합니다.
const HEADER_PATTERN = '요청 머리글의 JNDI 원격 조회';
const QUERY_PATTERN = '요청 인자의 JNDI 원격 조회';
const SCANNER_PATTERN = '취약점 점검 흔적과 원격 조회의 동시 일치';
const NO_PATTERN = '근거 패턴 없음';
// 가상 경보용 기준이며 Apache·MITRE의 공식 임계값이 아닙니다.
const HIGH_RULE_LEVEL = 10;
const MAX_TEXT = 8192;

function inspect(value) {
  if (typeof value !== 'string' || value.length > MAX_TEXT) return '';
  let text = value;
  for (let pass = 0; pass < 2; pass += 1) {
    try {
      const decoded = decodeURIComponent(text);
      if (decoded.length > MAX_TEXT || decoded === text) break;
      text = decoded;
    } catch { break; }
  }
  return text;
}

function remoteLookup(value) {
  // 문자열을 검사할 뿐 원격 주소를 조회하거나 구문을 실행하지 않습니다.
  return /\$\{\s*jndi\s*:\s*(?:ldaps?|rmi|dns|iiop|https?)\s*:\/\/[^\s{}\/]+(?:\/[^\s{}]*)?\s*\}/iu.test(inspect(value));
}

function validSource(value) {
  if (typeof value !== 'string') return false;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/u.test(value)) {
    return value.split('.').every(part => Number(part) <= 255);
  }
  // IPv6는 구문 검증을 통과한 주소만 받으며 네트워크를 사용하지 않습니다.
  if (!/^[a-f\d:]{3,39}$/iu.test(value) || !value.includes(':')) return false;
  try { return new URL(`http://[${value}]/`).hostname.length > 2; } catch { return false; }
}

function result(confidence, reason) {
  return {
    action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence,
    reason,
  };
}

export function decide(alert) {
  const description = inspect(alert?.rule?.description);
  const data = alert?.data;
  const level = Number.isInteger(alert?.rule?.level) && alert.rule.level >= 0
    && alert.rule.level <= 16 ? alert.rule.level : null;
  const headerValues = [data?.useragent];
  if (data?.headers && typeof data.headers === 'object' && !Array.isArray(data.headers)) {
    headerValues.push(...Object.values(data.headers).slice(0, 32));
  }
  const headerLookup = headerValues.some(remoteLookup);
  const url = typeof data?.url === 'string' && data.url.length <= MAX_TEXT ? data.url : '';
  const query = url.includes('?') ? url.slice(url.indexOf('?') + 1).split('#', 1)[0] : '';
  const queryLookup = remoteLookup(query);
  const scanner = /알려진\s*취약점\s*점검|취약점\s*(?:스캐너|점검\s*도구)|(?:log4j|log4shell)[- _]?(?:scan|scanner|check)/iu.test(description);
  const pattern = scanner && (headerLookup || queryLookup) ? SCANNER_PATTERN
    : headerLookup ? HEADER_PATTERN : queryLookup ? QUERY_PATTERN : NO_PATTERN;
  if (headerLookup || queryLookup) {
    return result(validSource(data?.srcip) && level >= HIGH_RULE_LEVEL ? 0.95 : 0.75, pattern);
  }
  // 이름·불완전한 구문·점검 흔적만 있는 사건은 차단하지 않습니다.
  const weakEvidence = /CVE-2021-44228|jndi|log4shell|취약점|원격\s*조회|조회\s*(?:구문|형태)|악용\s*구문|라이브러리|점검\s*도구/iu.test(description);
  if (weakEvidence || scanner || level >= HIGH_RULE_LEVEL) {
    const weakPattern = scanner || /점검\s*도구/iu.test(description) ? SCANNER_PATTERN
      : /머리글/iu.test(description) ? HEADER_PATTERN : QUERY_PATTERN;
    return result(0.6, weakPattern);
  }
  return result(0.1, NO_PATTERN);
}
