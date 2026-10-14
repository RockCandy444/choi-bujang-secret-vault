import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { previewPolicyRestore } from '../src/policy-preview.mjs';
import { readInput } from './policy-input.mjs';

const project = fileURLToPath(new URL('../', import.meta.url));
const fail = code => { throw new Error(code); };

export async function runPolicyPreview(args = []) {
  // No flags selects the user-requested pinned Git baseline. Explicit legacy
  // inputs/trust-key flags continue to select the signed-copy workflow.
  if (!args.includes('--inputs') && !args.includes('--trust-key')) {
    const { runGitPolicyPreview } = await import('./git-policy-preview.mjs');
    return runGitPolicyPreview(args);
  }
  let inputs = resolve(project, 'local-only/policy-preview');
  // The trust anchor is deliberately separate from the backup input directory.
  let trustKey = resolve(project, 'local-only/policy-trust/public-key.pem');
  const seen = new Set();
  for (let i = 0; i < args.length; i += 2) {
    if (!['--inputs', '--trust-key'].includes(args[i]) || seen.has(args[i])
        || !args[i + 1] || args[i + 1].startsWith('--')) fail('PREVIEW_ARGUMENT_INVALID');
    seen.add(args[i]);
    if (args[i] === '--inputs') inputs = resolve(args[i + 1]);
    else trustKey = resolve(args[i + 1]);
  }
  const safeCopy = await readInput(resolve(inputs, 'safe-decider.mjs'), 'SAFE_COPY_MISSING', 262144);
  const receiptBytes = await readInput(resolve(inputs, 'safe-receipt.json'), 'SAFE_COPY_VERIFICATION_MISSING', 4096);
  const signature = await readInput(resolve(inputs, 'safe-receipt.sig'), 'SAFE_COPY_VERIFICATION_MISSING', 64);
  const trustedPublicKey = (await readInput(trustKey, 'TRUST_ANCHOR_MISSING', 4096)).toString('utf8');
  let incidentAt;
  try {
    const context = JSON.parse((await readInput(resolve(inputs, 'incident.json'),
      'INCIDENT_TIME_MISSING', 128)).toString('utf8'));
    if (!context || Object.keys(context).join(',') !== 'incidentAt') fail('INCIDENT_TIME_INVALID');
    incidentAt = context.incidentAt;
  } catch (error) {
    if (['INCIDENT_TIME_MISSING', 'POLICY_INPUT_UNREADABLE', 'POLICY_INPUT_INVALID'].includes(error.message)) throw error;
    fail('INCIDENT_TIME_INVALID');
  }
  const trialPolicy = await readInput(resolve(inputs, 'trial-decider.mjs'), 'TRIAL_POLICY_MISSING', 262144);
  return previewPolicyRestore({ safeCopy, trialPolicy, receiptBytes, signature, trustedPublicKey, incidentAt });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const report = await runPolicyPreview(process.argv.slice(2));
    process.stdout.write(`시험 정책 → 안전 사본: 차이 미리보기\n${JSON.stringify(report, null, 2)}\n`);
  } catch (error) {
    const codes = new Set(['SAFE_COPY_MISSING', 'SAFE_COPY_VERIFICATION_MISSING',
      'TRUST_ANCHOR_MISSING', 'INCIDENT_TIME_MISSING', 'INCIDENT_TIME_INVALID',
      'TRIAL_POLICY_MISSING', 'PREVIEW_ARGUMENT_INVALID', 'POLICY_INPUT_INVALID',
      'POLICY_INPUT_TOO_LARGE', 'POLICY_INPUT_UNREADABLE', 'SAFE_COPY_VERIFICATION_FAILED',
      'PRE_INCIDENT_VERIFICATION_REQUIRED', 'GIT_BACKUP_UNAVAILABLE',
      'GIT_VERIFICATION_RECORD_INVALID', 'INCIDENT_EVIDENCE_INVALID',
      'TRIAL_POLICY_IS_OPERATIONAL']);
    const code = codes.has(error.message) ? error.message : 'PREVIEW_FAILED';
    process.stderr.write(`정책 미리보기 중단: ${code}\n`);
    process.exitCode = 1;
  }
}
