import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, writeFile, readFile, readdir, rm, link } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { readGitPolicyBaseline, BASELINE_COMMIT } from '../scripts/git-policy-preview.mjs';
import { prepareTrialRestore, runTrialRestore, requireNotesOnlyChange } from '../scripts/policy-restore.mjs';
import { checkDecider } from '../scripts/decider-test.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { createNoteOwnerVerifier } from '../src/verify-note-owner.mjs';

const baseline = readGitPolicyBaseline();
const safeText = baseline.safeCopy.toString('utf8');
const weakened = safeText.replace("return request.method === 'GET' && request.route === 'GET /api/my/notes';",
  'return true;').replace("const compositeRisk = request.signals.source === 'judge_fixture'", 'const compositeRisk = false');

async function withTrial(body) {
  const directory = await mkdtemp(join(tmpdir(), 'aleph-trial-restore-'));
  assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
  assert.ok(basename(directory).startsWith('aleph-trial-restore-'));
  const trialPath = join(directory, 'trial-decider.mjs');
  try {
    await writeFile(trialPath, weakened);
    // Test-only incident; never copied to the project or reported as real evidence.
    await writeFile(join(directory, 'incident.json'), JSON.stringify({ baselineCommit: BASELINE_COMMIT,
      source: 'operator_confirmed', incidentAt: new Date(Date.parse(baseline.recordedAt) + 60000).toISOString() }));
    await body({ directory, trialPath });
  } finally { await rm(directory, { recursive: true, force: true }); }
}

test('review shows version, target, scope and confirmation before creating or writing anything', async () => {
  await withTrial(async ({ directory, trialPath }) => {
    const before = await readFile(trialPath);
    const files = await readdir(directory);
    const review = await runTrialRestore({ directory });
    assert.equal(review.status, 'review_required');
    assert.equal(review.plan.restoreVersion, BASELINE_COMMIT);
    assert.equal(review.plan.target, 'local-only/policy-preview/trial-decider.mjs');
    assert.deepEqual(review.plan.restoreRegions, ['noteRoute', 'notes_decision_branch']);
    assert.match(review.plan.confirmation, /^[a-f0-9]{64}$/u);
    assert.ok(review.plan.changes.length > 0);
    assert.deepEqual(await readFile(trialPath), before);
    assert.deepEqual(await readdir(directory), files);
  });
});

test('confirmed restore changes only trial notes, retains audit prefix and passes decision fixtures', async () => {
  await withTrial(async ({ directory, trialPath }) => {
    const auditPath = join(directory, 'policy-restore-audit.jsonl');
    const auditBefore = '{"action":"fixture_previous_audit"}\n';
    const otherPath = join(directory, 'other-service.mjs');
    const otherBefore = 'fixture-other-service-rule\n';
    await writeFile(auditPath, auditBefore);
    await writeFile(otherPath, otherBefore);
    const operational = await readFile(new URL('../src/decider.mjs', import.meta.url));
    const context = await readFile(join(directory, 'incident.json'));
    const { plan } = await prepareTrialRestore(directory);
    const result = await runTrialRestore({ directory, confirmation: plan.confirmation });
    assert.equal(result.status, 'restored');
    assert.deepEqual(await readFile(trialPath), baseline.safeCopy);
    assert.equal(await readFile(otherPath, 'utf8'), otherBefore);
    assert.deepEqual(await readFile(join(directory, 'incident.json')), context);
    assert.deepEqual(await readFile(new URL('../src/decider.mjs', import.meta.url)), operational);
    const audit = await readFile(auditPath, 'utf8');
    assert.ok(audit.startsWith(auditBefore));
    const newRows = audit.slice(auditBefore.length).trim().split('\n').map(row => JSON.parse(row));
    assert.deepEqual(newRows.map(row => row.action), ['restore_attempt', 'restored']);
    assert.equal(newRows[0].beforeSha256, plan.trialSha256);
    assert.equal(newRows[1].afterSha256, plan.safeCopySha256);
    assert.equal(audit.includes('return true'), false);
    assert.equal((await readdir(directory)).some(name => name.startsWith('.policy-restore')), false);
    // Only the verified restored source is imported; never execute weakened input.
    const restored = await import(pathToFileURL(trialPath).href);
    const decisions = await checkDecider({ decide: restored.decide, ruleIds: restored.RULE_IDS });
    assert.equal(decisions.length, 10);
    assert.ok(decisions.every(item => item.passed));
    const { normal } = fixtureRequests();
    assert.equal((await restored.decide(normal)).decision, 'allow');
    const owner = createNoteOwnerVerifier({
      resolveSubject: async query => ({ ...query, userId: query.subjectId === 'subject_a_fixture'
        ? '00000000-0000-4000-8000-000000000001' : '00000000-0000-4000-8000-000000000002' }),
      readNoteOwner: async query => ({ id: query.noteId, owner_id: '00000000-0000-4000-8000-000000000001' }),
    });
    const scope = { classId: 'class_fixture', projectId: 'project_fixture',
      subjectId: 'subject_a_fixture', noteId: '00000000-0000-4000-8000-000000000003' };
    assert.equal(await owner(scope), true);
    assert.equal(await owner({ ...scope, subjectId: 'subject_b_fixture' }), false);
  });
});

test('unconfirmed or changed plans cannot write the trial or audit', async () => {
  await withTrial(async ({ directory, trialPath }) => {
    const { plan } = await prepareTrialRestore(directory);
    await assert.rejects(runTrialRestore({ directory, confirmation: '0'.repeat(64) }),
      { message: 'RESTORE_CONFIRMATION_MISMATCH' });
    const changed = weakened.replace('return true;', 'return false;');
    await writeFile(trialPath, changed);
    await assert.rejects(runTrialRestore({ directory, confirmation: plan.confirmation }),
      { message: 'RESTORE_CONFIRMATION_MISMATCH' });
    assert.equal(await readFile(trialPath, 'utf8'), changed);
    assert.deepEqual((await readdir(directory)).sort(), ['incident.json', 'trial-decider.mjs']);
  });
});

test('other-service, shared-rule and ambiguous boundary changes are rejected', () => {
  for (const trial of [
    weakened.replace("['POST', 'PUT', 'PATCH', 'DELETE']", "['GET']"),
    weakened.replace('request.deviceRegistered !== true', 'false'),
    weakened.replace("'notices_write_denied']);", "'new_rule']);"),
  ]) assert.throws(() => requireNotesOnlyChange(baseline.safeCopy, Buffer.from(trial)),
    { message: 'RESTORE_OUT_OF_SCOPE' });
  assert.throws(() => requireNotesOnlyChange(baseline.safeCopy,
    Buffer.from(weakened.replace('function noteRoute(request)', 'function changedRoute(request)'))),
  { message: 'RESTORE_SCOPE_UNCONFIRMED' });
});

test('existing restore lock, hardlinked target and unsafe audit stop before replacement', async () => {
  await withTrial(async ({ directory, trialPath }) => {
    const { plan } = await prepareTrialRestore(directory);
    const lockPath = join(directory, '.policy-restore.lock');
    await writeFile(lockPath, 'fixture-lock');
    await assert.rejects(runTrialRestore({ directory, confirmation: plan.confirmation }), { message: 'RESTORE_BUSY' });
    assert.equal(await readFile(lockPath, 'utf8'), 'fixture-lock');
    await rm(lockPath);
    await link(trialPath, join(directory, 'linked-trial.mjs'));
    await assert.rejects(runTrialRestore({ directory, confirmation: plan.confirmation }), { message: 'RESTORE_TARGET_UNSAFE' });
    await rm(join(directory, 'linked-trial.mjs'));
    await writeFile(join(directory, 'policy-restore-audit.jsonl'), 'fixture-truncated-record');
    await assert.rejects(runTrialRestore({ directory, confirmation: plan.confirmation }), { message: 'RESTORE_AUDIT_UNSAFE' });
    assert.equal(await readFile(trialPath, 'utf8'), weakened);
    assert.equal(await readFile(join(directory, 'policy-restore-audit.jsonl'), 'utf8'), 'fixture-truncated-record');
    assert.equal((await readdir(directory)).some(name => name.startsWith('.policy-restore')), false);
  });
});

test('same policy stays unchanged and absent incident evidence never reaches restoration', async () => {
  await withTrial(async ({ directory, trialPath }) => {
    await writeFile(trialPath, baseline.safeCopy);
    const { plan } = await prepareTrialRestore(directory);
    assert.deepEqual(plan.changes, []);
    assert.equal((await runTrialRestore({ directory, confirmation: plan.confirmation })).status, 'no_change');
    assert.deepEqual((await readdir(directory)).sort(), ['incident.json', 'trial-decider.mjs']);
    await rm(join(directory, 'incident.json'));
    await assert.rejects(runTrialRestore({ directory }), { message: 'INCIDENT_TIME_MISSING' });
    assert.deepEqual(await readFile(trialPath), baseline.safeCopy);
  });
});
