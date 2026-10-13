const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value)
  && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const identifier = value => typeof value === 'string' && value.length > 0
  && value.length <= 256 && value === value.trim() && !/[\u0000-\u001f\u007f]/u.test(value);

// Server-only adapter. Neither reader may come from an HTTP request.
// resolveSubject must read an operator-verified engine-to-Auth binding.
// readNoteOwner must read the stored owner, never client/user metadata.
// No real binding store is supplied by the current engine contract.
export function createNoteOwnerVerifier({ resolveSubject, readNoteOwner } = {}) {
  return async function verifyNoteOwner(scope) {
    if (typeof resolveSubject !== 'function' || typeof readNoteOwner !== 'function'
        || !record(scope) || Object.keys(scope).length !== 4
        || !['classId', 'projectId', 'subjectId', 'noteId'].every(key => Object.hasOwn(scope, key))
        || !['classId', 'projectId', 'subjectId'].every(key => identifier(scope[key]))
        || typeof scope.noteId !== 'string' || !UUID.test(scope.noteId)) return false;
    // Snapshot before awaiting readers so caller mutations cannot switch scope.
    const { classId, projectId, subjectId } = scope;
    const noteId = scope.noteId.toLowerCase();
    try {
      const binding = await resolveSubject(Object.freeze({ classId, projectId, subjectId }));
      if (!record(binding) || binding.classId !== classId || binding.projectId !== projectId
          || binding.subjectId !== subjectId || typeof binding.userId !== 'string'
          || !UUID.test(binding.userId)) return false;
      const userId = binding.userId.toLowerCase();
      const note = await readNoteOwner(Object.freeze({ classId, projectId, noteId }));
      return record(note) && typeof note.id === 'string' && UUID.test(note.id)
        && note.id.toLowerCase() === noteId && typeof note.owner_id === 'string'
        && UUID.test(note.owner_id) && note.owner_id.toLowerCase() === userId;
    } catch {
      // Do not log exceptions, user IDs, note IDs, credentials, or note bodies.
      return false;
    }
  };
}
