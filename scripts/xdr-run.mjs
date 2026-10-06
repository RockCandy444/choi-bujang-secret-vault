import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const MODULE_KEYS = ['brute-force', 'web-injection', 'known-cve', 'persistence', 'privilege', 'exfiltration'];
const ACTIONS = new Set(['block', 'alert', 'record']);

export function isDecision(value) {
  return Boolean(value)
    && typeof value === 'object'
    && !Array.isArray(value)
    && ACTIONS.has(value.action)
    && typeof value.confidence === 'number'
    && Number.isFinite(value.confidence)
    && value.confidence >= 0
    && value.confidence <= 1
    && typeof value.reason === 'string';
}

export async function runXdr({ root, moduleKey, writeError = (line) => console.error(line) }) {
  if (!MODULE_KEYS.includes(moduleKey)) {
    throw new Error('moduleKey 가 없습니다. brute-force, web-injection, known-cve, persistence, privilege, exfiltration 중 하나를 넣습니다.');
  }
  const fixture = JSON.parse(await readFile(join(root, 'xdr', 'fixtures', `${moduleKey}.json`), 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== moduleKey || !Array.isArray(fixture.alerts)) {
    throw new Error('경보 묶음 형식이 아닙니다.');
  }
  const loaded = await import(pathToFileURL(join(root, 'xdr', moduleKey, 'decide.mjs')).href);
  if (typeof loaded.decide !== 'function') throw new Error('decide 함수를 내보내지 않았습니다.');

  const decisions = [];
  const counts = { block: 0, alert: 0, record: 0 };
  for (const alert of fixture.alerts) {
    const alertId = alert && typeof alert.id === 'string' ? alert.id : '';
    let action = 'record';
    let confidence = 0;
    let reason = '반환 형식이 아닙니다';
    try {
      const out = await loaded.decide(alert);
      if (isDecision(out)) {
        action = out.action;
        confidence = out.confidence;
        reason = out.reason;
      } else {
        writeError(`형식 오류: ${alertId || '(id 없음)'}`);
      }
    } catch {
      writeError(`형식 오류: ${alertId || '(id 없음)'}`);
    }
    decisions.push({ alertId, action, confidence, reason });
    counts[action] += 1;
  }

  const result = { schema: 'aleph.xdr.result.v1', moduleKey, decisions, counts };
  const outDir = join(root, 'xdr', moduleKey);
  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, 'result.json'), `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  return result;
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  try {
    await runXdr({ root, moduleKey: process.argv[2] });
  } catch (error) {
    console.error(error instanceof Error ? error.message : '실행 오류');
    process.exitCode = 1;
  }
}
