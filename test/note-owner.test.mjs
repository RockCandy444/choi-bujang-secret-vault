import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { createNoteOwnerVerifier } from '../src/verify-note-owner.mjs';

// Memory-only fixtures do not register actual students or engine identities.
const userA = randomUUID();
const userB = randomUUID();
const noteId = randomUUID();
const scope = { classId: 'class_fixture', projectId: 'project_fixture',
  subjectId: 'subject_a_fixture', noteId };
const bindingA = { classId: scope.classId, projectId: scope.projectId,
  subjectId: scope.subjectId, userId: userA };

test('verified A binding matches stored owner; verified B binding cannot open A note', async () => {
  const verifier = createNoteOwnerVerifier({
    resolveSubject: async query => ({ ...query,
      userId: query.subjectId === 'subject_a_fixture' ? userA : userB }),
    readNoteOwner: async query => ({ id: query.noteId, owner_id: userA }),
  });
  assert.equal(await verifier(scope), true);
  assert.equal(await verifier({ ...scope, subjectId: 'subject_b_fixture' }), false);
});

test('absent binding, wrong class/project/subject and malformed user IDs fail before reading notes', async () => {
  let reads = 0;
  for (const binding of [null, [], { ...bindingA, classId: 'other_class' },
    { ...bindingA, projectId: 'other_project' }, { ...bindingA, subjectId: 'other_subject' },
    { ...bindingA, userId: '' }, { ...bindingA, userId: scope.subjectId }]) {
    const verifier = createNoteOwnerVerifier({ resolveSubject: async () => binding,
      readNoteOwner: async () => { reads++; return { id: noteId, owner_id: userA }; } });
    assert.equal(await verifier(scope), false);
  }
  assert.equal(reads, 0);
  assert.equal(await createNoteOwnerVerifier()(scope), false);
});

test('missing notes, wrong IDs, absent owners and foreign owners never authorize', async () => {
  for (const note of [null, [], { id: randomUUID(), owner_id: userA },
    { id: noteId }, { id: noteId, owner_id: null }, { id: noteId, owner_id: userB },
    { id: noteId, owner_id: scope.subjectId }]) {
    const verifier = createNoteOwnerVerifier({ resolveSubject: async () => bindingA,
      readNoteOwner: async () => note });
    assert.equal(await verifier(scope), false);
  }
});

test('ownership revocation is read again on each call with no cached grant', async () => {
  let owner = userA;
  let reads = 0;
  const verifier = createNoteOwnerVerifier({ resolveSubject: async () => bindingA,
    readNoteOwner: async () => { reads++; return { id: noteId, owner_id: owner }; } });
  assert.equal(await verifier(scope), true);
  owner = userB;
  assert.equal(await verifier(scope), false);
  assert.equal(reads, 2);
});

test('client authority fields and malformed scopes cannot trigger trusted readers', async () => {
  let reads = 0;
  const read = async () => { reads++; throw new Error('Must not read'); };
  const verifier = createNoteOwnerVerifier({ resolveSubject: read, readNoteOwner: read });
  for (const value of [null, {}, { ...scope, noteId: 'export' },
    { ...scope, classId: '' }, { ...scope, projectId: ' other ' },
    { ...scope, subjectId: '\nsubject' }, { ...scope, owner_id: userA },
    { ...scope, role: 'instructor' }, { ...scope, userId: userA }]) {
    assert.equal(await verifier(value), false);
  }
  assert.equal(reads, 0);
});

test('lookup failures fail closed without leaking reader output or logging errors', async () => {
  const saved = { log: console.log, warn: console.warn, error: console.error };
  const logs = [];
  for (const method of Object.keys(saved)) console[method] = (...args) => logs.push(args);
  try {
    for (const failedReader of ['resolveSubject', 'readNoteOwner']) {
      const readers = { resolveSubject: async () => bindingA,
        readNoteOwner: async () => ({ id: noteId, owner_id: userA }) };
      readers[failedReader] = async () => { throw new Error('Synthetic private upstream detail'); };
      assert.equal(await createNoteOwnerVerifier(readers)(scope), false);
    }
    assert.deepEqual(logs, []);
  } finally { Object.assign(console, saved); }
});

test('an in-flight caller cannot switch the class, subject or selected note', async () => {
  let release;
  const mutable = { ...scope };
  const verifier = createNoteOwnerVerifier({
    resolveSubject: query => new Promise(resolve => {
      assert.ok(Object.isFrozen(query));
      release = () => resolve(bindingA);
    }),
    readNoteOwner: async query => {
      assert.ok(Object.isFrozen(query));
      assert.equal(query.noteId, noteId);
      assert.equal(query.classId, scope.classId);
      return { id: noteId, owner_id: userA };
    },
  });
  const pending = verifier(mutable);
  mutable.classId = 'other_class';
  mutable.subjectId = 'subject_b_fixture';
  mutable.noteId = randomUUID();
  release();
  assert.equal(await pending, true);
});
