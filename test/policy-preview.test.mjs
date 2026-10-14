import assert from 'node:assert/strict';
import test from 'node:test';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, mkdir, readFile, readdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { previewPolicyRestore, policyDigest } from '../src/policy-preview.mjs';
import { runPolicyPreview } from '../scripts/policy-preview.mjs';
import { BASELINE_COMMIT, readGitPolicyBaseline, previewGitBaseline } from '../scripts/git-policy-preview.mjs';

const VERIFIED = '2026-10-01T00:00:00.000Z';
const INCIDENT = '2026-10-02T00:00:00.000Z';
const NOW = Date.parse('2026-10-03T00:00:00.000Z');

function fixture({ safe = 'header\ndeny\nfooter\n', trial = 'header\nallow\nfooter\n', receipt = {} } = {}) {
  // Disposable verification key, never written or printed; not a device key.
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const safeCopy = Buffer.from(safe);
  const record = { schema: 'aleph.policy-safe-copy.v1', version: 'fixture-v9',
    scope: 'src/decider.mjs', verifiedAt: VERIFIED, verification: 'passed',
    policySha256: policyDigest(safeCopy), ...receipt };
  const receiptBytes = Buffer.from(JSON.stringify(record));
  return { safeCopy, trialPolicy: Buffer.from(trial), receiptBytes,
    signature: sign(null, receiptBytes, privateKey),
    trustedPublicKey: publicKey.export({ type: 'spki', format: 'pem' }),
    incidentAt: INCIDENT, now: NOW };
}

test('verified pre-incident copy shows version and exact trial-to-copy scope without source', () => {
  const inputs = fixture();
  const report = previewPolicyRestore(inputs);
  assert.equal(report.mode, 'preview_only');
  assert.equal(report.restoreVersion, 'fixture-v9');
  assert.deepEqual(report.changedFiles, ['src/decider.mjs']);
  assert.deepEqual(report.changes, [{ trial: { startLine: 2, lineCount: 1 },
    safeCopy: { startLine: 2, lineCount: 1 } }]);
  assert.equal(report.removedTrialLines, 1);
  assert.equal(report.addedSafeLines, 1);
  assert.equal(report.trialSha256, policyDigest(inputs.trialPolicy));
  assert.equal(JSON.stringify(report).includes('allow'), false);
  assert.equal(JSON.stringify(report).includes('footer'), false);
});

test('same policy, inserted lines and removed lines have the expected direction', () => {
  assert.deepEqual(previewPolicyRestore(fixture({ safe: 'same\n', trial: 'same\n' })).changes, []);
  assert.deepEqual(previewPolicyRestore(fixture({ safe: 'a\nb\nc', trial: 'a\nc' })).changes,
    [{ trial: { startLine: 2, lineCount: 0 }, safeCopy: { startLine: 2, lineCount: 1 } }]);
  assert.deepEqual(previewPolicyRestore(fixture({ safe: 'a\nc', trial: 'a\nb\nc' })).changes,
    [{ trial: { startLine: 2, lineCount: 1 }, safeCopy: { startLine: 2, lineCount: 0 } }]);
  assert.equal(previewPolicyRestore(fixture({ safe: 'a\n', trial: 'a' })).changes.length, 1);
});

test('absent copy and tampered copy, receipt, signature or verifier stop without a report', () => {
  const original = fixture();
  for (const input of [
    { ...original, safeCopy: undefined },
    { ...original, safeCopy: Buffer.alloc(0) },
    { ...original, safeCopy: Buffer.from('tampered') },
    { ...original, receiptBytes: Buffer.from('{}') },
    { ...original, signature: Buffer.alloc(64) },
    { ...original, signature: undefined },
    { ...original, trustedPublicKey: fixture().trustedPublicKey },
    { ...original, trustedPublicKey: '' },
  ]) assert.throws(() => previewPolicyRestore(input), { message: /^(SAFE_COPY_MISSING|SAFE_COPY_VERIFICATION_FAILED)$/u });
});

test('signed failed validation, wrong scope, extra fields and invalid versions are rejected', () => {
  for (const receipt of [
    { verification: 'failed' }, { scope: 'other-service' }, { extra: true },
    { schema: 'unknown' }, { version: ['fixture-v9'] }, { version: 'invalid\nversion' },
  ]) assert.throws(() => previewPolicyRestore(fixture({ receipt })), { message: 'SAFE_COPY_VERIFICATION_FAILED' });
});

test('verification must precede a valid past incident strictly', () => {
  for (const incidentAt of [VERIFIED, '2026-09-30T00:00:00.000Z',
    '2026-10-04T00:00:00.000Z', 'unknown', '2026-10-02']) {
    assert.throws(() => previewPolicyRestore({ ...fixture(), incidentAt }), { message: 'PRE_INCIDENT_VERIFICATION_REQUIRED' });
  }
});

test('oversized or malformed source stops, policy bodies and error values never leave the boundary', () => {
  assert.throws(() => previewPolicyRestore(fixture({ trial: 'x'.repeat(262145) })), { message: 'POLICY_INPUT_INVALID' });
  assert.throws(() => previewPolicyRestore(fixture({ trial: 'x\n'.repeat(2001) })), { message: 'POLICY_INPUT_TOO_LARGE' });
  assert.throws(() => previewPolicyRestore({ ...fixture(), trialPolicy: Buffer.from([0xff]) }), { message: 'POLICY_INPUT_INVALID' });
  const marker = 'private-content-fixture-must-not-be-printed';
  const report = previewPolicyRestore(fixture({ trial: marker }));
  assert.equal(JSON.stringify(report).includes(marker), false);
});

test('CLI reads only local inputs, never imports either policy or writes any existing file', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'aleph-policy-preview-'));
  // Confirm the absolute cleanup target stays inside the named temp directory.
  assert.equal(dirname(resolve(temp)), resolve(tmpdir()));
  assert.ok(basename(temp).startsWith('aleph-policy-preview-'));
  try {
    const inputsDir = join(temp, 'inputs');
    await mkdir(inputsDir);
    const inputs = fixture({ trial: "throw new Error('must-never-execute-policy');\n" });
    const files = {
      'safe-decider.mjs': inputs.safeCopy, 'trial-decider.mjs': inputs.trialPolicy,
      'safe-receipt.json': inputs.receiptBytes, 'safe-receipt.sig': inputs.signature,
      'incident.json': Buffer.from(JSON.stringify({ incidentAt: INCIDENT })),
    };
    for (const [name, bytes] of Object.entries(files)) await writeFile(join(inputsDir, name), bytes);
    const publicPath = join(temp, 'trusted-public.pem');
    await writeFile(publicPath, inputs.trustedPublicKey);
    const args = ['--inputs', inputsDir, '--trust-key', publicPath];
    const beforeProduction = await readFile(new URL('../src/decider.mjs', import.meta.url));
    const beforeConfig = await readFile(new URL('../aleph.config.json', import.meta.url));
    const report = await runPolicyPreview(args);
    assert.equal(report.restoreVersion, 'fixture-v9');
    const result = spawnSync(process.execPath,
      [fileURLToPath(new URL('../scripts/policy-preview.mjs', import.meta.url)), ...args], { encoding: 'utf8' });
    assert.equal(result.status, 0);
    assert.equal(result.stderr, '');
    assert.equal(result.stdout.includes('must-never-execute-policy'), false);
    for (const [name, bytes] of Object.entries(files)) assert.deepEqual(await readFile(join(inputsDir, name)), bytes);
    assert.deepEqual((await readdir(inputsDir)).sort(), Object.keys(files).sort());
    assert.deepEqual(await readFile(publicPath, 'utf8'), inputs.trustedPublicKey);
    assert.deepEqual(await readFile(new URL('../src/decider.mjs', import.meta.url)), beforeProduction);
    assert.deepEqual(await readFile(new URL('../aleph.config.json', import.meta.url)), beforeConfig);
    await rm(join(inputsDir, 'safe-decider.mjs'));
    const stopped = spawnSync(process.execPath,
      [fileURLToPath(new URL('../scripts/policy-preview.mjs', import.meta.url)), ...args], { encoding: 'utf8' });
    assert.equal(stopped.status, 1);
    assert.equal(stopped.stdout, '');
    assert.equal(stopped.stderr, '정책 미리보기 중단: SAFE_COPY_MISSING\n');
  } finally { await rm(temp, { recursive: true, force: true }); }
});

function gitFixture() {
  const baseline = readGitPolicyBaseline();
  const recorded = Date.parse(baseline.recordedAt);
  // Simulated incident context for tests only, not evidence of a real incident.
  return { baseline, incidentRecord: { baselineCommit: BASELINE_COMMIT,
    source: 'operator_confirmed', incidentAt: new Date(recorded + 60000).toISOString() },
  now: recorded + 120000 };
}

test('pinned Git version and same-commit check record reach the preview without signed-copy files', () => {
  const input = gitFixture();
  const report = previewGitBaseline({ ...input, trialPolicy: input.baseline.safeCopy });
  assert.equal(report.restoreVersion, BASELINE_COMMIT);
  assert.equal(report.verificationRecordedAt, input.baseline.recordedAt);
  assert.equal(report.verification.source, 'committed_readme_local_checks');
  assert.equal(report.verification.localChecks, 108);
  assert.deepEqual(report.changedFiles, []);
  assert.deepEqual(report.changes, []);
  assert.equal(Object.hasOwn(report, 'verifiedAt'), false);
});

test('Git preview reports changed ranges only after pre-incident evidence passes', () => {
  const input = gitFixture();
  const marker = 'fixture-source-must-not-be-printed';
  const report = previewGitBaseline({ ...input,
    trialPolicy: Buffer.concat([Buffer.from(`${marker}\n`), input.baseline.safeCopy]) });
  assert.deepEqual(report.changes, [{ trial: { startLine: 1, lineCount: 1 },
    safeCopy: { startLine: 1, lineCount: 0 } }]);
  assert.equal(JSON.stringify(report).includes(marker), false);
});

test('unavailable Git copy or missing/failed committed verification prevents comparison', () => {
  const input = gitFixture();
  for (const baseline of [undefined, { ...input.baseline, commit: 'wrong' },
    { ...input.baseline, safeCopy: Buffer.alloc(0) }]) {
    assert.throws(() => previewGitBaseline({ ...input, baseline }), { message: 'GIT_BACKUP_UNAVAILABLE' });
  }
  assert.throws(() => previewGitBaseline({ ...input,
    baseline: { ...input.baseline, verificationRecord: Buffer.from('failed local check') } }),
  { message: 'GIT_VERIFICATION_RECORD_INVALID' });
});

test('Git commit time alone, new test results and unconfirmed incident do not authorize differences', () => {
  const input = gitFixture();
  for (const incidentRecord of [undefined, {}, { ...input.incidentRecord, source: 'guessed' },
    { ...input.incidentRecord, baselineCommit: 'wrong' }, { ...input.incidentRecord, extra: true }]) {
    assert.throws(() => previewGitBaseline({ ...input, incidentRecord }), { message: 'INCIDENT_EVIDENCE_INVALID' });
  }
  for (const incidentAt of [input.baseline.recordedAt, 'unknown',
    new Date(Date.parse(input.baseline.recordedAt) - 60000).toISOString(),
    new Date(input.now + 60000).toISOString()]) {
    assert.throws(() => previewGitBaseline({ ...input,
      incidentRecord: { ...input.incidentRecord, incidentAt } }),
    { message: 'PRE_INCIDENT_VERIFICATION_REQUIRED' });
  }
});

test('Git CLI changes no input or operational file and rejects operational trial aliases', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'aleph-policy-git-'));
  assert.equal(dirname(resolve(temp)), resolve(tmpdir()));
  assert.ok(basename(temp).startsWith('aleph-policy-git-'));
  try {
    const input = gitFixture();
    const trialPath = join(temp, 'trial.mjs');
    const contextPath = join(temp, 'incident.json');
    const trial = Buffer.concat([Buffer.from("throw new Error('must-not-run-trial');\n"), input.baseline.safeCopy]);
    const context = JSON.stringify(input.incidentRecord);
    await writeFile(trialPath, trial);
    await writeFile(contextPath, context);
    const before = await readFile(new URL('../src/decider.mjs', import.meta.url));
    const args = ['--git-backup', 'a446a9a', '--trial', trialPath, '--incident-record', contextPath];
    const report = await runPolicyPreview(args);
    assert.equal(report.restoreVersion, BASELINE_COMMIT);
    assert.equal(report.removedTrialLines, 1);
    const cli = fileURLToPath(new URL('../scripts/policy-preview.mjs', import.meta.url));
    const result = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
    assert.equal(result.status, 0);
    assert.equal(result.stderr, '');
    assert.equal(result.stdout.includes('must-not-run-trial'), false);
    assert.deepEqual(await readFile(trialPath), trial);
    assert.equal(await readFile(contextPath, 'utf8'), context);
    assert.deepEqual(await readFile(new URL('../src/decider.mjs', import.meta.url)), before);
    assert.deepEqual((await readdir(temp)).sort(), ['incident.json', 'trial.mjs']);
    await assert.rejects(runPolicyPreview(['--trial',
      fileURLToPath(new URL('../src/decider.mjs', import.meta.url)), '--incident-record', contextPath]),
    { message: 'TRIAL_POLICY_IS_OPERATIONAL' });
    await assert.rejects(runPolicyPreview(['--trial', join(temp, 'absent.mjs'), '--incident-record', contextPath]),
      { message: 'TRIAL_POLICY_MISSING' });
    const stopped = spawnSync(process.execPath, [cli, '--incident-record', join(temp, 'absent.json')], { encoding: 'utf8' });
    assert.equal(stopped.status, 1);
    assert.equal(stopped.stdout, '');
    assert.equal(stopped.stderr, '정책 미리보기 중단: INCIDENT_TIME_MISSING\n');
  } finally { await rm(temp, { recursive: true, force: true }); }
});

test('Git options cannot select a different baseline or bypass verification with mixed modes', async () => {
  await assert.rejects(runPolicyPreview(['--git-backup', 'HEAD']), { message: 'GIT_BACKUP_UNAVAILABLE' });
  await assert.rejects(runPolicyPreview(['--git-backup', 'a446a9a', '--inputs', 'unused']),
    { message: 'PREVIEW_ARGUMENT_INVALID' });
  await assert.rejects(runPolicyPreview(['--trial', 'one', '--trial', 'two']),
    { message: 'PREVIEW_ARGUMENT_INVALID' });
});
