import { randomUUID } from 'node:crypto';
import { lstat, open, rename, unlink } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { policyDigest } from '../src/policy-preview.mjs';
import { readGitPolicyBaseline, runGitPolicyPreview } from './git-policy-preview.mjs';
import { readInput } from './policy-input.mjs';

const project = fileURLToPath(new URL('../', import.meta.url));
const defaultDirectory = resolve(project, 'local-only/policy-preview');
const fail = code => { throw new Error(code); };
const TARGET = 'local-only/policy-preview/trial-decider.mjs';

// Restore only the two notes-specific regions in this known source version.
// Every byte outside them, including notice rules and shared guards, must match.
// Ambiguous or changed boundaries fail closed; no trial code is executed.
export function requireNotesOnlyChange(safeCopy, trialPolicy) {
  const anchors = ['function noteRoute(request) {\n',
    '\nfunction noticeWriteRoute(request) {', '  if (noteRoute(request)) {\n',
    "\n  return {\n    schema: 'aleph.decision.v1',\n    requestId: request.requestId,\n    decision: 'deny',\n    reasonCode: 'starter_not_ready',\n    ruleIds: ['resource_route'],\n  };\n}\n"];
  const protectedParts = bytes => {
    const source = bytes.toString('utf8');
    const offsets = anchors.map(anchor => {
      const offset = source.indexOf(anchor);
      if (offset < 0 || source.indexOf(anchor, offset + 1) >= 0) fail('RESTORE_SCOPE_UNCONFIRMED');
      return offset;
    });
    if (offsets.some((offset, index) => index > 0 && offset <= offsets[index - 1])) {
      fail('RESTORE_SCOPE_UNCONFIRMED');
    }
    return [source.slice(0, offsets[0]), source.slice(offsets[1], offsets[2]), source.slice(offsets[3])];
  };
  const safe = protectedParts(safeCopy);
  const trial = protectedParts(trialPolicy);
  if (safe.some((part, index) => part !== trial[index])) fail('RESTORE_OUT_OF_SCOPE');
}

export async function prepareTrialRestore(directory = defaultDirectory) {
  const trialPath = resolve(directory, 'trial-decider.mjs');
  const report = await runGitPolicyPreview(['--trial', trialPath,
    '--incident-record', resolve(directory, 'incident.json')]);
  const baseline = readGitPolicyBaseline();
  const trial = await readInput(trialPath, 'TRIAL_POLICY_MISSING', 262144);
  if (policyDigest(trial) !== report.trialSha256 || policyDigest(baseline.safeCopy) !== report.safeCopySha256) {
    fail('RESTORE_INPUT_CHANGED');
  }
  requireNotesOnlyChange(baseline.safeCopy, trial);
  const plan = { ...report, mode: 'restore_plan', target: TARGET,
    restoreRegions: ['noteRoute', 'notes_decision_branch'] };
  return { plan: { ...plan, confirmation: policyDigest(Buffer.from(JSON.stringify(plan))) },
    safeCopy: baseline.safeCopy };
}

async function appendAudit(handle, plan, action) {
  const row = { schema: 'aleph.trial-policy-audit.v1', at: new Date().toISOString(),
    action, version: plan.restoreVersion, target: TARGET, confirmation: plan.confirmation,
    beforeSha256: plan.trialSha256, afterSha256: plan.safeCopySha256 };
  await handle.writeFile(`${JSON.stringify(row)}\n`);
  await handle.sync();
}

// CLI uses the fixed ignored trial directory only. An explicit directory is
// for local fixture tests, never a remote endpoint or the operational policy.
export async function runTrialRestore({ confirmation, directory = defaultDirectory } = {}) {
  const prepared = await prepareTrialRestore(directory);
  if (confirmation === undefined) return { status: 'review_required', plan: prepared.plan };
  if (typeof confirmation !== 'string' || confirmation !== prepared.plan.confirmation) {
    fail('RESTORE_CONFIRMATION_MISMATCH');
  }
  if (prepared.plan.changes.length === 0) return { status: 'no_change', plan: prepared.plan };
  // Refuse filesystem redirections before creating a lock or appending audit.
  const dirStat = await lstat(directory);
  const targetPath = resolve(directory, 'trial-decider.mjs');
  const targetStat = await lstat(targetPath);
  if (!dirStat.isDirectory() || dirStat.isSymbolicLink()
      || !targetStat.isFile() || targetStat.isSymbolicLink() || targetStat.nlink !== 1) {
    fail('RESTORE_TARGET_UNSAFE');
  }
  const lockPath = resolve(directory, '.policy-restore.lock');
  const tempPath = resolve(directory, `.policy-restore-${randomUUID()}.tmp`);
  const auditPath = resolve(directory, 'policy-restore-audit.jsonl');
  let lock;
  let temporary;
  let audit;
  let applied = false;
  try {
    try { lock = await open(lockPath, 'wx'); }
    catch (error) { fail(error.code === 'EEXIST' ? 'RESTORE_BUSY' : 'RESTORE_IO_FAILED'); }
    const current = await prepareTrialRestore(directory);
    if (current.plan.confirmation !== confirmation) fail('RESTORE_INPUT_CHANGED');
    try {
      const auditStat = await lstat(auditPath);
      if (!auditStat.isFile() || auditStat.isSymbolicLink() || auditStat.nlink !== 1) fail('RESTORE_AUDIT_UNSAFE');
      const oldAudit = await readInput(auditPath, 'RESTORE_IO_FAILED', 1048576);
      if (oldAudit.length && oldAudit[oldAudit.length - 1] !== 10) fail('RESTORE_AUDIT_UNSAFE');
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    audit = await open(auditPath, 'a');
    temporary = await open(tempPath, 'wx');
    await temporary.writeFile(current.safeCopy);
    await temporary.sync();
    await temporary.close(); temporary = undefined;
    await appendAudit(audit, current.plan, 'restore_attempt');
    // Recheck receipt, incident, protected regions and trial bytes just before
    // the atomic replacement. Cooperative restorers share the exclusive lock.
    const finalCheck = await prepareTrialRestore(directory);
    if (finalCheck.plan.confirmation !== confirmation) fail('RESTORE_INPUT_CHANGED');
    const finalStat = await lstat(targetPath);
    if (!finalStat.isFile() || finalStat.isSymbolicLink() || finalStat.nlink !== 1) fail('RESTORE_TARGET_UNSAFE');
    await rename(tempPath, targetPath);
    applied = true;
    await appendAudit(audit, current.plan, 'restored');
    return { status: 'restored', version: current.plan.restoreVersion,
      target: TARGET, afterSha256: current.plan.safeCopySha256 };
  } catch (error) {
    if (applied) fail('RESTORE_APPLIED_AUDIT_INCOMPLETE');
    if (error.message.startsWith('RESTORE_') || error.message.startsWith('INCIDENT_')
        || error.message.startsWith('PRE_INCIDENT_') || error.message.startsWith('TRIAL_')
        || error.message.startsWith('GIT_') || error.message.startsWith('POLICY_')) throw error;
    fail('RESTORE_IO_FAILED');
  } finally {
    let cleanupFailed = false;
    try { await temporary?.close(); } catch { cleanupFailed = true; }
    try { await audit?.close(); } catch { cleanupFailed = true; }
    if (lock) {
      // Only these exact files created by this invocation are removed.
      try { await unlink(tempPath); } catch (error) { if (error.code !== 'ENOENT') cleanupFailed = true; }
      try { await lock.close(); } catch { cleanupFailed = true; }
      try { await unlink(lockPath); } catch { cleanupFailed = true; }
    }
    if (cleanupFailed) fail(applied ? 'RESTORE_APPLIED_CLEANUP_INCOMPLETE' : 'RESTORE_CLEANUP_INCOMPLETE');
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 0 && (args.length !== 2 || args[0] !== '--confirm'
        || !/^[a-f0-9]{64}$/u.test(args[1]))) fail('RESTORE_ARGUMENT_INVALID');
    const result = await runTrialRestore({ confirmation: args[1] });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (result.status === 'review_required') {
      process.stdout.write('버전·대상·변경 범위를 확인한 뒤 --confirm 값으로 다시 실행하세요.\n');
    }
  } catch (error) {
    const known = /^(?:RESTORE_[A-Z_]+|GIT_BACKUP_UNAVAILABLE|GIT_VERIFICATION_RECORD_INVALID|INCIDENT_TIME_MISSING|INCIDENT_EVIDENCE_INVALID|PRE_INCIDENT_VERIFICATION_REQUIRED|TRIAL_POLICY_MISSING|TRIAL_POLICY_IS_OPERATIONAL|POLICY_INPUT_(?:INVALID|UNREADABLE|TOO_LARGE))$/u;
    const code = known.test(error.message) ? error.message : 'RESTORE_IO_FAILED';
    process.stderr.write(`시험 정책 복원 중단: ${code}\n`);
    process.exitCode = 1;
  }
}
