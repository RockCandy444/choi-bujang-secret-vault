import { createHash, createPublicKey, verify } from 'node:crypto';

const SCOPE = 'src/decider.mjs';
const MAX_BYTES = 256 * 1024;
const MAX_LINES = 2000;
const fail = code => { throw new Error(code); };
export const policyDigest = bytes => createHash('sha256').update(bytes).digest('hex');

function isoTime(value) {
  return typeof value === 'string' && value.length === 24
    && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}

export function requirePreIncidentTime(recordedAt, incidentAt, now = Date.now()) {
  if (!isoTime(recordedAt) || !isoTime(incidentAt) || !Number.isFinite(now)
      || Date.parse(incidentAt) > now || Date.parse(recordedAt) >= Date.parse(incidentAt)) {
    fail('PRE_INCIDENT_VERIFICATION_REQUIRED');
  }
}

function sourceLines(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > MAX_BYTES) {
    fail('POLICY_INPUT_INVALID');
  }
  let lines;
  try { lines = new TextDecoder('utf-8', { fatal: true }).decode(bytes).split('\n'); }
  catch { fail('POLICY_INPUT_INVALID'); }
  if (lines.length > MAX_LINES) fail('POLICY_INPUT_TOO_LARGE');
  return lines;
}

// Compare exact lines, including CR and the final newline. Only ranges leave this
// function: policy source, comments and embedded values never enter the report.
function changedRanges(trial, safe) {
  const width = safe.length + 1;
  const lengths = new Uint16Array((trial.length + 1) * width);
  for (let i = trial.length - 1; i >= 0; i--) {
    for (let j = safe.length - 1; j >= 0; j--) {
      lengths[i * width + j] = trial[i] === safe[j]
        ? 1 + lengths[(i + 1) * width + j + 1]
        : Math.max(lengths[(i + 1) * width + j], lengths[i * width + j + 1]);
    }
  }
  const ranges = [];
  let i = 0;
  let j = 0;
  let range;
  const finish = () => {
    if (range) ranges.push(range);
    range = undefined;
  };
  while (i < trial.length || j < safe.length) {
    if (i < trial.length && j < safe.length && trial[i] === safe[j]) {
      finish(); i++; j++; continue;
    }
    range ??= { trial: { startLine: i + 1, lineCount: 0 },
      safeCopy: { startLine: j + 1, lineCount: 0 } };
    if (i < trial.length && (j === safe.length
        || lengths[(i + 1) * width + j] >= lengths[i * width + j + 1])) {
      range.trial.lineCount++; i++;
    } else {
      range.safeCopy.lineCount++; j++;
    }
  }
  finish();
  return ranges;
}

// Byte comparison only; callers must verify their own evidence before calling.
export function comparePolicyBytes(safeCopy, trialPolicy) {
  const changes = changedRanges(sourceLines(trialPolicy), sourceLines(safeCopy));
  return {
    trialSha256: policyDigest(trialPolicy), safeCopySha256: policyDigest(safeCopy),
    changedFiles: changes.length ? [SCOPE] : [],
    removedTrialLines: changes.reduce((sum, item) => sum + item.trial.lineCount, 0),
    addedSafeLines: changes.reduce((sum, item) => sum + item.safeCopy.lineCount, 0), changes,
  };
}

// Local preview contract, separate from the engine request/response contract.
// A trusted verifier signs the exact receipt bytes BEFORE the incident.
// This verifies that attestation and byte integrity; it does not execute code,
// independently certify safety, or change policy/files/DB/audit history.
export function previewPolicyRestore({ safeCopy, trialPolicy, receiptBytes,
  signature, trustedPublicKey, incidentAt, now = Date.now() }) {
  if (!Buffer.isBuffer(safeCopy) || safeCopy.length === 0) fail('SAFE_COPY_MISSING');
  if (!Buffer.isBuffer(receiptBytes) || receiptBytes.length === 0
      || receiptBytes.length > 4096 || !Buffer.isBuffer(signature) || signature.length !== 64) {
    fail('SAFE_COPY_VERIFICATION_FAILED');
  }
  try {
    if (typeof trustedPublicKey !== 'string'
        || !trustedPublicKey.startsWith('-----BEGIN PUBLIC KEY-----')
        || trustedPublicKey.length > 4096) fail('SAFE_COPY_VERIFICATION_FAILED');
    const key = createPublicKey(trustedPublicKey);
    if (key.asymmetricKeyType !== 'ed25519' || !verify(null, receiptBytes, key, signature)) {
      fail('SAFE_COPY_VERIFICATION_FAILED');
    }
  } catch { fail('SAFE_COPY_VERIFICATION_FAILED'); }
  let receipt;
  try { receipt = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(receiptBytes)); }
  catch { fail('SAFE_COPY_VERIFICATION_FAILED'); }
  const keys = ['schema', 'version', 'scope', 'verifiedAt', 'verification', 'policySha256'];
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)
      || Object.keys(receipt).length !== keys.length || !keys.every(key => Object.hasOwn(receipt, key))
      || receipt.schema !== 'aleph.policy-safe-copy.v1' || receipt.scope !== SCOPE
      || typeof receipt.version !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,63}$/u.test(receipt.version)
      || receipt.verification !== 'passed' || !isoTime(receipt.verifiedAt)
      || typeof receipt.policySha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(receipt.policySha256)
      || receipt.policySha256 !== policyDigest(safeCopy)) {
    fail('SAFE_COPY_VERIFICATION_FAILED');
  }
  requirePreIncidentTime(receipt.verifiedAt, incidentAt, now);
  return {
    schema: 'aleph.policy-preview.v1', mode: 'preview_only',
    restoreVersion: receipt.version, scope: SCOPE,
    verifiedAt: receipt.verifiedAt, incidentAt,
    ...comparePolicyBytes(safeCopy, trialPolicy),
  };
}
