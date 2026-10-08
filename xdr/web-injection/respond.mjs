// 거부 규칙 후보와 알림을 기록합니다. 판단은 독립된 decide.mjs에 맡깁니다.
// 현재 ZTNA 계약에는 경보 IP를 검증된 주체·기기에 연결하는 인터페이스가 없습니다.
// 연결 전에는 후보를 비활성으로 보관하고 기존 판정기·규칙을 변경하지 않습니다.
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
  '요청 인자의 SQL 구문 삽입',
  '요청 인자의 스크립트 태그 삽입',
  '요청 인자의 상위 경로 이동 반복',
]);
const STATUSES = new Set(['pending_verified_binding', 'suppressed_normal_source', 'expired_candidate']);
const hash = value => createHash('sha256').update(value).digest('hex');
const isHash = value => typeof value === 'string' && /^[a-f0-9]{64}$/u.test(value);

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
  return Number.isFinite(time) && time <= 8.64e15 - TTL_MS ? time : null;
}

function safeId(alert) {
  return typeof alert?.id === 'string' && /^wi-\d{2,6}$/u.test(alert.id) ? alert.id : null;
}

function validCandidate(rule) {
  if (!rule || typeof rule !== 'object' || Array.isArray(rule)
      || Object.keys(rule).sort().join(',')
        !== 'action,active,alertIds,createdAt,expiresAt,match,pattern,ruleId,sourceIpSha256,status') return false;
  return /^xdr\.web_injection\.[a-f0-9]{64}$/u.test(rule.ruleId)
    && rule.action === 'deny' && rule.active === false && rule.match === null
    && Array.isArray(rule.alertIds) && rule.alertIds.length === 1
    && /^wi-\d{2,6}$/u.test(rule.alertIds[0])
    && isHash(rule.sourceIpSha256) && PATTERNS.has(rule.pattern) && STATUSES.has(rule.status)
    && typeof rule.createdAt === 'string' && typeof rule.expiresAt === 'string'
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(rule.createdAt)
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(rule.expiresAt)
    && Date.parse(rule.expiresAt) - Date.parse(rule.createdAt) === TTL_MS
    && rule.ruleId === `xdr.web_injection.${hash(`${rule.sourceIpSha256}|${rule.alertIds[0]}|${rule.createdAt}`)}`;
}

export async function respond(alerts, { root = ROOT, now = Date.now() } = {}) {
  if (!Array.isArray(alerts) || !Number.isFinite(now) || Math.abs(now) > 8.64e15) {
    throw new Error('invalid_response_input');
  }
  const candidatePath = join(root, 'xdr', 'web-injection', 'deny-candidates.json');
  let previous = { schema: SCHEMA, normalSources: [], rules: [] };
  try {
    previous = JSON.parse(await readFile(candidatePath, 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw new Error('invalid_candidate_file');
  }
  if (previous?.schema !== SCHEMA || !Array.isArray(previous.rules)
      || previous.rules.some(rule => !validCandidate(rule))
      || !Array.isArray(previous.normalSources) || previous.normalSources.some(source => !isHash(source))) {
    throw new Error('invalid_candidate_file');
  }

  const decisions = alerts.map(alert => decide(alert));
  // 정상 경보가 먼저 들어온 경우도 기억합니다. 공유 주소 전체를 거부하지 않습니다.
  const normalSources = new Set(previous.normalSources);
  for (const [index, alert] of alerts.entries()) {
    const source = sourceHash(alert);
    const at = eventTime(alert);
    if (decisions[index].action === 'record' && source && safeId(alert)
        && at !== null && at <= now + 5000) normalSources.add(source);
  }
  const rules = new Map(previous.rules.map(rule => [rule.ruleId, rule]));
  for (const rule of rules.values()) {
    if (normalSources.has(rule.sourceIpSha256)) rule.status = 'suppressed_normal_source';
    else if (Date.parse(rule.expiresAt) <= now) rule.status = 'expired_candidate';
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
        // 사건 시각에서 만료를 계산하므로 재전송은 만료를 연장하지 않습니다.
        ruleId = `xdr.web_injection.${hash(`${source}|${alertId}|${createdAt}`)}`;
        const existing = rules.get(ruleId);
        status = existing?.status === 'suppressed_normal_source' ? 'suppressed_normal_source'
          : observedAt + TTL_MS <= now ? 'expired_candidate' : 'pending_verified_binding';
        rules.set(ruleId, {
          ruleId, action: 'deny', active: false, match: null,
          sourceIpSha256: source, alertIds: [alertId], createdAt, expiresAt,
          pattern: decision.reason, status,
        });
        if (status === 'suppressed_normal_source') counts.suppressed += 1;
        else counts.candidates += 1;
        if (status === 'expired_candidate') counts.expired += 1;
      }
    }
    notices.push({
      at: new Date(now).toISOString(), moduleKey: 'web-injection', alertId,
      action: decision.action, confidence: decision.confidence,
      pattern: PATTERNS.has(decision.reason) ? decision.reason : '근거 패턴 없음',
      status, ruleId, expiresAt,
    });
  }

  await mkdir(join(root, 'xdr', 'web-injection'), { recursive: true });
  await writeFile(candidatePath, `${JSON.stringify({ schema: SCHEMA, normalSources: [...normalSources], rules: [...rules.values()] }, null, 2)}\n`, { mode: 0o600 });
  if (notices.length) {
    await appendFile(join(root, 'xdr', 'alerts.log'), notices.map(row => JSON.stringify(row) + '\n').join(''), { mode: 0o600 });
  }
  return { counts, notices: notices.length, ztnaConnected: false };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    const fixture = JSON.parse(await readFile(new URL('../fixtures/web-injection.json', import.meta.url), 'utf8'));
    if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'web-injection') throw new Error();
    const result = await respond(fixture.alerts);
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.stdout.write('로컬 거부 후보 기록입니다. 운영 연결이 없어 ZTNA 자동 적용·정상 통과는 확인하지 못했습니다.\n');
  } catch {
    process.stderr.write('경보 대응 기록 실패: 입력 형식과 후보 파일·로그 저장 상태를 확인하세요.\n');
    process.exitCode = 1;
  }
}
