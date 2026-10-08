// patterns.json의 네 패턴을 그대로 옮긴 상수입니다. 이 파일만으로 판단합니다.
const PATTERNS = Object.freeze([
  Object.freeze({
    name: '요청 인자의 SQL 구문 삽입',
    condition: '요청 인자에 SQL 조건식이나 조회 구문을 이어 붙이는 형태가 있거나, 경보 설명에 SQL 구문 삽입이 명시된 경우를 찾는다. 같은 출발 주소의 시각·횟수·설명으로 반복 정도를 함께 확인하되 반복 횟수의 수치 기준은 여기서 임의로 정하지 않는다. 따옴표 하나, select·SQL이라는 수업명이나 검색어만으로는 일치시키지 않는다.',
    evidence: 'MITRE ATT&CK T1190은 외부 공개 앱의 취약점 악용을 설명하고 APT28 등의 외부 웹사이트 SQL 주입 사례를 제시한다: https://attack.mitre.org/techniques/T1190/',
  }),
  Object.freeze({
    name: '요청 인자의 스크립트 태그 삽입',
    condition: '요청 인자에 <script> 같은 스크립트 태그 형태 또는 인코딩된 동등 형태가 있거나, 경보 설명에 스크립트 삽입 표식이 명시된 경우를 찾는다. 같은 출발 주소에서 해당 표식이 반복되는 정도를 시각·횟수·설명과 함께 확인한다. script·스크립트라는 수업 단어만으로는 일치시키지 않으며, 태그 표식만으로 실제 스크립트 실행이나 침입 성공을 확정하지 않는다.',
    evidence: 'MITRE ATT&CK T1190의 공개 웹 앱 취약점 악용 범주에 참고 신호로 연결한 해석이며, 스크립트 삽입 형태는 MITRE CWE-79의 XSS 설명을 보조 근거로 삼고 태그만으로 T1190 성립을 확정하지 않는다: https://attack.mitre.org/techniques/T1190/ 및 https://cwe.mitre.org/data/definitions/79.html',
  }),
  Object.freeze({
    name: '요청 인자의 상위 경로 이동 반복',
    condition: '파일·경로 요청 인자에 ../ 또는 인코딩된 동등 형태로 상위 경로를 거슬러 올라가는 표기가 반복되거나, 경보 설명에 여러 단계의 경로 이동·경로 이탈 반복이 명시된 경우를 찾는다. 한 인자 안의 이동 반복과 같은 출발 주소의 요청 반복을 구분하여 시각·횟수·설명으로 확인한다. up이라는 단어나 정상 파일 이름만으로는 일치시키지 않으며, 표식만으로 허용 경로 밖의 파일 접근 성공을 확정하지 않는다.',
    evidence: 'MITRE ATT&CK T1190의 C0017 사례는 공개 앱의 디렉터리 경로 이탈 취약점 악용을 포함하며, ../를 통한 상위 경로 이동 형태는 MITRE CWE-22의 경로 이탈 설명을 따른다: https://attack.mitre.org/techniques/T1190/ 및 https://cwe.mitre.org/data/definitions/22.html',
  }),
  Object.freeze({
    name: '요청 인자의 명령 구분자 삽입',
    condition: '경보 설명에 요청 인자의 명령 구분자 삽입 표기가 명시된 경우를 찾는다. 같은 출발 주소의 연속 요청에서 해당 표기가 반복된다는 횟수·설명과 높은 규칙 수준이 함께 확인될 때만 차단 후보로 본다. 단순한 이름 구분 문자, 한 번의 의심 표기, 높은 수준만으로는 차단하지 않으며 실제 명령 실행 성공도 확정하지 않는다.',
    evidence: 'MITRE ATT&CK T1190의 Cutting Edge 사례는 외부 공개 Ivanti 앱의 명령 주입 취약점 악용을 포함하며, 명령 구분자 등 특수 요소를 통한 명령 주입 형태는 MITRE CWE-78을 보조 근거로 삼는다: https://attack.mitre.org/techniques/T1190/ 및 https://cwe.mitre.org/data/definitions/78.html',
  }),
]);
const NO_PATTERN = '근거 패턴 없음';
// 아래 수준·횟수·확신도는 가상 경보용 판단 기준이며 MITRE의 공식 수치가 아닙니다.
const HIGH_LEVEL = 10;
const REPEATED_REQUESTS = 3;

function text(value) {
  return typeof value === 'string' ? value.slice(0, 8192) : '';
}

function count(value) {
  if (typeof value === 'string' && /^\d{1,9}$/u.test(value)) value = Number(value);
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function decode(value) {
  let decoded = value.replace(/\+/gu, ' ');
  for (let pass = 0; pass < 3; pass += 1) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch { break; }
  }
  return decoded;
}

function argumentValues(url) {
  const question = url.indexOf('?');
  if (question === -1) return [];
  // 인자 값별로 대조합니다. 키 이름과 URL 경로는 SQL 구문 대조에서 제외합니다.
  return url.slice(question + 1).split('#')[0].split('&').map(parameter => {
    const equals = parameter.indexOf('=');
    return equals === -1 ? '' : decode(parameter.slice(equals + 1));
  });
}

function result(confidence, reason) {
  return {
    action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence,
    // 원문·식별자·비밀값을 노출하지 않고 고정된 이름만 반환합니다.
    reason,
  };
}

export function decide(alert) {
  const description = text(alert?.rule?.description);
  const rawLevel = alert?.rule?.level;
  const level = Number.isInteger(rawLevel) && rawLevel >= 0 && rawLevel <= 16 ? rawLevel : null;
  const values = argumentValues(text(alert?.data?.url));
  const describedCount = description.match(/(\d+)\s*(?:번|건|회)/u);
  const requestCount = count(alert?.data?.count) ?? count(describedCount?.[1]);
  // 이번 명령 구분자 후보는 가상 경보의 유효한 IPv4 출발 주소와 반복 근거를 확인합니다.
  const source = alert?.data?.srcip;
  const sourceKnown = typeof source === 'string' && /^\d{1,3}(?:\.\d{1,3}){3}$/u.test(source)
    && source.split('.').every(part => Number(part) <= 255);
  const denied = /삽입\s*표식(?:은|이)?\s*아(?:닙|니)|공격\s*표기(?:는|가)?\s*없/u.test(description);

  // 이어진 구문 또는 경보에 명시된 설명을 확인합니다.
  const sqlArgument = values.some(value =>
    /\bunion\s+(?:all\s+)?select\b|\bselect\s+[^;]+\s+from\b|;\s*(?:select|insert|update|delete|drop)\b/iu.test(value)
    || /\b(?:or|and)\s+(?:\d+\s*=\s*\d+|'[^']*'\s*=\s*'[^']*')/iu.test(value));
  const scriptArgument = values.some(value => /<\s*script(?:\s[^>]*|)>/iu.test(value));
  const traversalDepth = values.reduce((maximum, value) =>
    Math.max(maximum, (value.match(/\.\.\//gu) ?? []).length), 0);
  const sqlDescription = !denied && /SQL\s*(?:구문|표식|삽입|주입)|데이터베이스\s*조회.*이어\s*붙/iu.test(description);
  const scriptDescription = !denied && /스크립트\s*(?:삽입|표식|태그)/u.test(description);
  const traversalDescription = !denied && /경로.*(?:거슬러|이탈)/u.test(description);
  const commandDescription = !denied && /명령\s*구분자\s*(?:삽입\s*)?(?:표기|표식)/u.test(description);
  const commandRepeated = /연속\s*요청|같은\s*주소.*반복/u.test(description);
  const matches = [
    sqlArgument || sqlDescription,
    scriptArgument || scriptDescription,
    traversalDepth > 0 || traversalDescription,
    commandDescription,
  ];

  let confidence = 0;
  let reason = NO_PATTERN;
  for (let index = 0; index < matches.length; index += 1) {
    if (!matches[index]) continue;
    // 단일 표식은 검토 대상으로, 반복과 높은 규칙 수준이 함께 있으면 뚜렷한 일치로 봅니다.
    let score = 0.7;
    if (requestCount !== null && requestCount >= REPEATED_REQUESTS) {
      const repetitionConfirmed = index !== 3 || (sourceKnown && commandRepeated);
      score = level !== null && level >= HIGH_LEVEL && repetitionConfirmed ? 0.95 : 0.8;
    }
    if (index === 2 && traversalDepth >= 2) {
      score = Math.max(score, level !== null && level >= HIGH_LEVEL ? 0.9 : 0.8);
    }
    if (score > confidence) {
      confidence = score;
      reason = PATTERNS[index].name;
    }
  }
  if (confidence > 0) return result(confidence, reason);

  // 정상 활동의 설명과 낮은 규칙 수준을 확인합니다. 높은 수준만으로 차단하지 않습니다.
  const normalDescription = /조회|화면|새로고침|로그아웃/u.test(description);
  const uncertainDescription = /이상한|주입|구분\s*문자|명령\s*구분자|삽입|경로\s*이탈/u.test(description)
    && !denied;
  if (level !== null && level <= 3 && normalDescription && !uncertainDescription) {
    return result(0.1, NO_PATTERN);
  }
  // 범위 밖의 형태나 근거가 부족한 경보는 근거 패턴 없음으로 검토 대상에 남깁니다.
  return result(0.5, NO_PATTERN);
}
