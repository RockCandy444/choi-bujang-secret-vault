// 경보 대응 기록과 거부 규칙 후보만 저장합니다. ZTNA 요청 계약을 확장하지 않습니다.
// IP를 요청의 검증된 주체·기기에 연결할 운영 인터페이스가 없어 자동 적용은 하지 않습니다.
import { createHash } from 'node:crypto';
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SCHEMA = 'aleph.xdr.deny-candidates.v1';
const TTL_MS = 15 * 60 * 1000;
const PATTERNS = new Set([
  '같은 주소의 짧은 시간 연속 로그인 실패',
  '여러 계정에 같은 비밀번호 대입',
]);
const hash = value => createHash('sha256').update(value).digest('hex');

function sourceHash(alert) {
  const source = alert?.data?.srcip;
  if (typeof source !== 'string' || source.includes('%') || !isIP(source)) return null;
  const canonical = isIP(source) === 6 ? new URL(`http://[${source}]/`).hostname : source;
  return hash(canonical);
}

function eventTime(alert) {
  const value = alert?.timestamp;
  if (typeof value !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/u.test(value)) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) ? time : null;
}

function safeId(alert) {
  return typeof alert?.id === 'string' && /^bf-\d{2,6}$/u.test(alert.id) ? alert.id : null;
}

function validCandidate(rule) {
  return rule && Object.keys(rule).sort().join(',')
    === 'action,active,alertIds,createdAt,expiresAt,match,pattern,ruleId,sourceIpSha256,status'
    && /^xdr\.brute_force\.[a-f0-9]{64}$/u.test(rule.ruleId)
    && rule.action === 'deny' && rule.active === false && rule.match === null
    && Array.isArray(rule.alertIds) && rule.alertIds.length === 1
    && /^bf-\d{2,6}$/u.test(rule.alertIds[0])
    && /^[a-f0-9]{64}$/u.test(rule.sourceIpSha256)
    && PATTERNS.has(rule.pattern)
    && ['pending_verified_binding', 'suppressed_normal_source'].includes(rule.status)
    && Number.isFinite(Date.parse(rule.createdAt))
    && Date.parse(rule.expiresAt) - Date.parse(rule.createdAt) === TTL_MS;
}

export async function respond(alerts, { root = ROOT, now = Date.now() } = {}) {
  if (!Array.isArray(alerts) || !Number.isFinite(now)) throw new Error('invalid_response_input');
  const candidatePath = join(root, 'xdr', 'brute-force', 'deny-candidates.json');
  let previous = { schema: SCHEMA, rules: [] };
  try {
    previous = JSON.parse(await readFile(candidatePath, 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw new Error('invalid_candidate_file');
  }
  if (previous?.schema !== SCHEMA || !Array.isArray(previous.rules)
      || previous.rules.some(rule => !validCandidate(rule))) throw new Error('invalid_candidate_file');

  const decisions = [];
  for (const alert of alerts) decisions.push(await decide(alert));
  // 같은 공유 주소의 정상 이벤트가 있으면 주소 전체를 거부하는 후보도 추가하지 않습니다.
  const normalSources = new Set(alerts.flatMap((alert, index) => {
    const source = sourceHash(alert);
    return decisions[index].action === 'record' && source ? [source] : [];
  }));
  const rules = new Map(previous.rules.map(rule => [rule.ruleId, rule]));
  for (const rule of rules.values()) {
    if (normalSources.has(rule.sourceIpSha256)) rule.status = 'suppressed_normal_source';
  }
  const notices = [];
  const counts = { block: 0, alert: 0, record: 0, candidates: 0, suppressed: 0, expired: 0, applied: 0 };
  for (const [index, alert] of alerts.entries()) {
    const decision = decisions[index];
    counts[decision.action] += 1;
    if (decision.action === 'record') continue;
    const alertId = safeId(alert);
    const source = sourceHash(alert);
    const observedAt = eventTime(alert);
    let status = 'notification_only';
    let ruleId = null;
    let expiresAt = null;
    if (decision.action === 'block' && decision.confidence >= 0.85 && PATTERNS.has(decision.reason)) {
      if (!alertId || !source || observedAt === null || observedAt > now + 5000) {
        status = 'insufficient_verified_data';
      } else if (normalSources.has(source)) {
        status = 'suppressed_normal_source';
        counts.suppressed += 1;
      } else {
        const createdAt = new Date(observedAt).toISOString();
        expiresAt = new Date(observedAt + TTL_MS).toISOString();
        // 재전송해도 원래 사건 시각에서 계산한 만료 시각을 연장하지 않습니다.
        ruleId = `xdr.brute_force.${hash(`${source}|${alertId}|${createdAt}`)}`;
        const existing = rules.get(ruleId);
        const suppressed = existing?.status === 'suppressed_normal_source';
        rules.set(ruleId, {
          ruleId, action: 'deny', active: false, match: null,
          sourceIpSha256: source, alertIds: [alertId], createdAt, expiresAt,
          pattern: decision.reason,
          status: suppressed ? 'suppressed_normal_source' : 'pending_verified_binding',
        });
        status = suppressed ? 'suppressed_normal_source'
          : observedAt + TTL_MS <= now ? 'expired_candidate' : 'pending_verified_binding';
        if (suppressed) counts.suppressed += 1;
        else counts.candidates += 1;
        if (observedAt + TTL_MS <= now) counts.expired += 1;
      }
    }
    notices.push({
      at: new Date(now).toISOString(), moduleKey: 'brute-force', alertId,
      action: decision.action, confidence: decision.confidence,
      pattern: PATTERNS.has(decision.reason) ? decision.reason : '근거 패턴 없음',
      status, ruleId, expiresAt,
    });
  }

  await mkdir(join(root, 'xdr', 'brute-force'), { recursive: true });
  await writeFile(candidatePath, `${JSON.stringify({ schema: SCHEMA, rules: [...rules.values()] }, null, 2)}\n`, { mode: 0o600 });
  if (notices.length) {
    await appendFile(join(root, 'xdr', 'alerts.log'), notices.map(row => JSON.stringify(row) + '\n').join(''), { mode: 0o600 });
  }
  return { counts, notices: notices.length };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    const fixture = JSON.parse(await readFile(new URL('../fixtures/brute-force.json', import.meta.url), 'utf8'));
    if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'brute-force') throw new Error();
    const result = await respond(fixture.alerts);
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.stdout.write('로컬 후보 기록입니다. 검증된 ZTNA 연결이 없어 자동 적용하지 않았습니다.\n');
  } catch {
    process.stderr.write('경보 대응 기록 실패: 입력 형식과 후보 파일·로그 저장 상태를 확인하세요.\n');
    process.exitCode = 1;
  }
}
