// patterns.json의 두 패턴을 코드로 대조합니다. 심판 환경에서는 JSON을 import하지 않습니다.
const FAILURE_PATTERN = '같은 주소의 짧은 시간 연속 로그인 실패';
const SPRAY_PATTERN = '여러 계정에 같은 비밀번호 대입';
const NO_PATTERN = '근거 패턴 없음';
const JEV_ENDPOINT = 'https://api.typesafe.ai/v1/systemone';
const JEV_TIMEOUT_MS = 1000;

// 가상 경보의 강한 신호를 고르는 로컬 기준이며 MITRE의 공식 수치가 아닙니다.
const HIGH_RULE_LEVEL = 10;
const MANY_FAILURES = 15;

function count(value) {
  if (typeof value === 'string' && /^\d{1,9}$/u.test(value)) value = Number(value);
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function signals(alert) {
  // 실행기의 원본 경보와 read-alerts.mjs가 뽑은 다섯 필드를 모두 받습니다.
  const rawDescription = alert?.rule?.description ?? alert?.description;
  const description = typeof rawDescription === 'string' ? rawDescription.slice(0, 2048) : '';
  const rawLevel = alert?.rule?.level ?? alert?.level;
  const ruleLevel = Number.isInteger(rawLevel) && rawLevel >= 0 && rawLevel <= 16 ? rawLevel : null;
  const source = alert?.data?.srcip ?? alert?.srcip;
  const sourceKnown = typeof source === 'string'
    && (/^(?:\d{1,3}\.){3}\d{1,3}$/u.test(source)
      ? source.split('.').every(part => Number(part) <= 255)
      : /^[a-f\d:]{3,39}$/iu.test(source) && source.includes(':'));
  const describedFailures = description.match(/실패(?:가|는)?\s*(\d+)\s*건/u);
  const failureCount = count(alert?.data?.count) ?? count(describedFailures?.[1]);
  const describedAccounts = description.match(/계정\s*(\d+)\s*개/u);
  const accountCount = count(describedAccounts?.[1]);
  const hasFailures = /실패|failed\s+(?:login|logon|authentication)|authentication\s+failure/iu.test(description);
  const samePassword = /같은\s*비밀번호|동일한?\s*비밀번호|same\s+password/iu.test(description);
  const multipleAccounts = /여러\s*계정|서로\s*다른\s*계정|계정\s*이름을|multiple\s+accounts/iu.test(description)
    || accountCount > 1;
  const passwordAttempts = /비밀번호.*(?:대입|넣었|시도)/u.test(description);
  const windowMatch = description.match(/(\d+)\s*(분|초)\s*(?:안|동안)/u);
  const windowSeconds = windowMatch ? Number(windowMatch[1]) * (windowMatch[2] === '분' ? 60 : 1) : null;
  const successAfterFailures = /뒤(?:에)?\s*(?:다시\s*)?성공|이후\s*성공/iu.test(description);
  const benignEvent = /로그인(?:이)?\s*성공|로그아웃|비밀번호\s*변경(?:이)?\s*성공|세션\s*유지|로그인\s*상태.*유지|자료실\s*화면.*열/u.test(description);
  return {
    ruleLevel, sourceKnown, failureCount, accountCount, hasFailures, samePassword,
    multipleAccounts, passwordAttempts, windowSeconds, successAfterFailures, benignEvent,
    unusualSource: /평소와\s*다른\s*주소/u.test(description),
    regularAttempts: /같은\s*간격|연속|이어졌|쌓였/u.test(description),
    passwordChanges: /비밀번호.*(?:바꿔|변경\s*화면)/u.test(description),
    lockedAccount: /잠금/u.test(description),
  };
}

function result(confidence, reason) {
  return {
    action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence,
    reason,
  };
}

async function askJev(facts, pattern) {
  // 키는 호출할 때만 서버 환경에서 읽습니다. import 시점에는 요구하지 않습니다.
  // 공식 계약: https://docs.typesafe.ai/api (noul은 공격일 가능성 0~1).
  const apiKey = typeof process === 'undefined' ? undefined : process.env?.TYPESAFE_API_KEY;
  if (typeof apiKey !== 'string' || !apiKey.trim() || typeof fetch !== 'function'
      || typeof AbortController !== 'function' || typeof setTimeout !== 'function'
      || typeof clearTimeout !== 'function') return null;

  const controller = new AbortController();
  let timer;
  try {
    const timeout = new Promise(resolveTimeout => {
      timer = setTimeout(() => { controller.abort(); resolveTimeout(null); }, JEV_TIMEOUT_MS);
    });
    const request = async () => {
      const response = await fetch(JEV_ENDPOINT, {
        method: 'POST',
        redirect: 'error',
        signal: controller.signal,
        headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        // 숫자·사실 여부만 보내고 원문·주소·계정 식별자는 전송하지 않습니다.
        body: JSON.stringify({
          model: 'jev-latest',
          state: { facts, candidatePattern: pattern },
          questions: {
            brute_force: {
              type: 'noul',
              instructions: 'Do these authentication facts indicate a deliberate brute-force attack rather than ordinary user mistakes? Missing facts are unknown, not proof of attack.',
              criteria: {
                true: 'Repeated concentrated authentication failures or the same password tried across multiple accounts (MITRE ATT&CK T1110).',
                false: 'Normal activity or a small number of user mistakes; several accounts alone do not prove the same password was used.',
              },
            },
          },
        }),
      });
      if (!response.ok) return null;
      const body = await response.json();
      const answer = body?.answers?.brute_force;
      const confidence = answer?.noul;
      return answer?.type === 'noul' && typeof confidence === 'number'
        && Number.isFinite(confidence) && confidence >= 0 && confidence <= 1 ? confidence : null;
    };
    return await Promise.race([request(), timeout]);
  } catch {
    // HTTP 오류·비밀키·응답 원문을 기록하거나 reason에 넣지 않습니다.
    return null;
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}

export async function decide(alert) {
  const facts = signals(alert);
  const pattern = facts.samePassword && facts.multipleAccounts ? SPRAY_PATTERN
    : facts.hasFailures ? FAILURE_PATTERN : NO_PATTERN;
  const clearSpray = pattern === SPRAY_PATTERN && (facts.hasFailures || facts.passwordAttempts);
  const volume = facts.failureCount ?? facts.accountCount;
  const clearFailures = facts.sourceKnown && facts.hasFailures
    && facts.ruleLevel >= HIGH_RULE_LEVEL && volume !== null && volume >= MANY_FAILURES;
  if (clearSpray || clearFailures) return result(0.95, pattern);

  // 알려진 정상 활동과 성공 전 한 번의 실수는 Jev를 부르지 않습니다.
  const normal = facts.ruleLevel !== null && facts.ruleLevel <= 3
    && ((!facts.hasFailures && facts.benignEvent)
      || (facts.successAfterFailures && facts.failureCount !== null && facts.failureCount <= 1));
  if (normal) return result(0.1, NO_PATTERN);

  // 키 없음·예외·잘못된 값·1초 제한 초과는 모두 검토 대상으로 남깁니다.
  const confidence = await askJev(facts, pattern);
  return result(confidence ?? 0.5, pattern);
}
