import { execFileSync } from 'node:child_process';
import { open } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { comparePolicyBytes, requirePreIncidentTime, policyDigest } from '../src/policy-preview.mjs';
import { readInput } from './policy-input.mjs';

export const BASELINE_COMMIT = 'a446a9a793f7712d0f0bf0d72b44e30a1eec0b26';
const project = fileURLToPath(new URL('../', import.meta.url));
const fail = code => { throw new Error(code); };

export function readGitPolicyBaseline() {
  // Fixed SHA and file paths; no shell, checkout, hooks, network, or source execution.
  const git = (...args) => execFileSync('git', ['--no-replace-objects', '-C', project, ...args], {
    maxBuffer: 262144, timeout: 5000, windowsHide: true,
    env: { ...process.env, GIT_OPTIONAL_LOCKS: '0', GIT_TERMINAL_PROMPT: '0' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  try {
    const commit = git('rev-parse', '--verify', `${BASELINE_COMMIT}^{commit}`).toString('utf8').trim();
    if (commit !== BASELINE_COMMIT) fail('GIT_BACKUP_UNAVAILABLE');
    const recordedAt = new Date(git('show', '--no-notes', '-s', '--format=%cI', commit).toString('utf8').trim()).toISOString();
    const safeCopy = git('cat-file', 'blob', `${commit}:src/decider.mjs`);
    const verificationRecord = git('cat-file', 'blob', `${commit}:README.md`);
    return { commit, recordedAt, safeCopy, verificationRecord };
  } catch { fail('GIT_BACKUP_UNAVAILABLE'); }
}

// Evidence is a committed local-check statement, not a signed independent
// safety certificate. Incident context must be confirmed separately by the
// operator; neither commit time nor today's test can establish incident time.
function verifyGitEvidence(baseline, incidentRecord, now) {
  if (baseline?.commit !== BASELINE_COMMIT || !Buffer.isBuffer(baseline.safeCopy)
      || baseline.safeCopy.length === 0 || !Buffer.isBuffer(baseline.verificationRecord)) {
    fail('GIT_BACKUP_UNAVAILABLE');
  }
  let readme;
  try { readme = new TextDecoder('utf-8', { fatal: true }).decode(baseline.verificationRecord); }
  catch { fail('GIT_VERIFICATION_RECORD_INVALID'); }
  const section = readme.split('## 9단계 저장점과 다시 실행')[1]?.split('\n## ')[0];
  if (!section?.includes('이번 저장점에서 전체 로컬 검사 108건, 탐지 연습 6건, 판정기 연습 10건과 9단계 로컬 빌드를 실제 실행해 통과했습니다.')) {
    fail('GIT_VERIFICATION_RECORD_INVALID');
  }
  const context = incidentRecord;
  if (!context || typeof context !== 'object' || Array.isArray(context)
      || Object.keys(context).sort().join(',') !== 'baselineCommit,incidentAt,source'
      || context.baselineCommit !== BASELINE_COMMIT || context.source !== 'operator_confirmed') {
    fail('INCIDENT_EVIDENCE_INVALID');
  }
  requirePreIncidentTime(baseline.recordedAt, context.incidentAt, now);
}

export function previewGitBaseline({ baseline, trialPolicy, incidentRecord, now = Date.now() }) {
  verifyGitEvidence(baseline, incidentRecord, now);
  return {
    schema: 'aleph.policy-preview.v1', mode: 'preview_only',
    restoreVersion: BASELINE_COMMIT, scope: 'src/decider.mjs',
    verificationRecordedAt: baseline.recordedAt, incidentAt: incidentRecord.incidentAt,
    verification: { source: 'committed_readme_local_checks', recordPath: 'README.md',
      recordSha256: policyDigest(baseline.verificationRecord),
      localChecks: 108, detectionFixtures: 6, decisionFixtures: 10 },
    ...comparePolicyBytes(baseline.safeCopy, trialPolicy),
  };
}

export async function runGitPolicyPreview(args = []) {
  let trialPath = resolve(project, 'local-only/policy-preview/trial-decider.mjs');
  let incidentPath = resolve(project, 'local-only/policy-preview/incident.json');
  const seen = new Set();
  for (let i = 0; i < args.length; i += 2) {
    if (!['--git-backup', '--trial', '--incident-record'].includes(args[i])
        || seen.has(args[i]) || !args[i + 1] || args[i + 1].startsWith('--')) {
      fail('PREVIEW_ARGUMENT_INVALID');
    }
    seen.add(args[i]);
    if (args[i] === '--git-backup') {
      if (![BASELINE_COMMIT, 'a446a9a'].includes(args[i + 1])) fail('GIT_BACKUP_UNAVAILABLE');
    } else if (args[i] === '--trial') trialPath = resolve(args[i + 1]);
    else incidentPath = resolve(args[i + 1]);
  }
  const baseline = readGitPolicyBaseline();
  let incidentRecord;
  const incidentBytes = await readInput(incidentPath, 'INCIDENT_TIME_MISSING', 1024);
  try { incidentRecord = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(incidentBytes)); }
  catch { fail('INCIDENT_EVIDENCE_INVALID'); }
  // Validate all evidence before reading/comparing any trial source.
  verifyGitEvidence(baseline, incidentRecord, Date.now());
  let operationalHandle;
  let operationalIdentity;
  try {
    operationalHandle = await open(resolve(project, 'src/decider.mjs'), 'r');
    operationalIdentity = await operationalHandle.stat({ bigint: true });
  } catch { fail('POLICY_INPUT_UNREADABLE'); }
  finally { await operationalHandle?.close(); }
  // Match the opened file, including alternate spellings, symlinks and hardlinks.
  // Identity is checked on the same handle that reads the trial bytes.
  const trialPolicy = await readInput(trialPath, 'TRIAL_POLICY_MISSING', 262144, operationalIdentity);
  return previewGitBaseline({ baseline, trialPolicy, incidentRecord });
}
