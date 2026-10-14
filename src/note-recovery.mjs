import { createHash } from 'node:crypto';

export const NOTE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const HASH = /^[a-f0-9]{64}$/u;
export const noteContentHash = (title, content) => createHash('sha256')
  .update(title, 'utf8').update(Buffer.from([0])).update(content, 'utf8').digest('hex');

const ERRORS = Object.freeze({
  NOTE_ALREADY_EXISTS: 409, NOTE_BACKUP_NOT_FOUND: 404,
  NOTE_BACKUP_INVALID: 409, NOTE_OWNER_CONFLICT: 409,
  NOTE_RESTORE_MISMATCH: 409, INVALID_NOTE: 400,
});

export function isJudgeB(login) {
  return login?.kind === 'judge' && login.identity === 'b'
    && typeof login.userId === 'string' && NOTE_UUID.test(login.userId)
    && typeof login.runId === 'string' && NOTE_UUID.test(login.runId);
}

// The caller supplies only a login established by createLoginVerifier.
// Client role, run, owner, content and hash never authorize restoration.
export async function callNoteRecovery({ operation, login, id, title, content, project, secret }) {
  if (!isJudgeB(login)) return { status: 403, error: 'TEST_B_REQUIRED' };
  if (typeof id !== 'string' || !NOTE_UUID.test(id)
      || !['create', 'restore'].includes(operation)) return { status: 400, error: 'INVALID_NOTE_ID' };
  const noteId = id.toLowerCase();
  const payload = { p_run_id: login.runId.toLowerCase(), p_owner_id: login.userId.toLowerCase(), p_note_id: noteId };
  if (operation === 'create') {
    if (typeof title !== 'string' || !title.trim() || title.length > 200
        || typeof content !== 'string' || content.length > 20000
        || title.includes('\0') || content.includes('\0')
        || (typeof secret === 'string' && secret && (title.includes(secret) || content.includes(secret)))) {
      return { status: 400, error: 'INVALID_NOTE' };
    }
    Object.assign(payload, { p_title: title, p_content: content, p_content_hash: noteContentHash(title, content) });
  }
  try {
    const upstream = await fetch(new URL(`/rest/v1/rpc/aleph_${operation}_test_note`, project), {
      method: 'POST', headers: { apikey: secret, 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(payload), signal: AbortSignal.timeout(10000), redirect: 'error', cache: 'no-store',
    });
    const result = await upstream.json();
    if (!upstream.ok) {
      if (['PGRST202', '42883', '42P01'].includes(result?.code)) {
        return { status: 503, error: 'NOTE_RECOVERY_NOT_CONFIGURED' };
      }
      if (result?.code === 'P0001' && Object.hasOwn(ERRORS, result.message)) {
        return { status: ERRORS[result.message], error: result.message };
      }
      throw new Error('unavailable');
    }
    if (!result || Array.isArray(result)
        || Object.keys(result).sort().join(',') !== 'content_hash,id,owner_id'
        || result.id !== noteId || result.owner_id !== payload.p_owner_id
        || typeof result.content_hash !== 'string' || !HASH.test(result.content_hash)
        || (operation === 'create' && result.content_hash !== payload.p_content_hash)) {
      throw new Error('invalid_result');
    }
    return { status: operation === 'create' ? 201 : 200,
      result: { id: result.id, ownerId: result.owner_id, contentHash: result.content_hash } };
  } catch {
    // Never print upstream errors, metadata, credentials or note source.
    return { status: 502, error: 'NOTE_RECOVERY_UNAVAILABLE' };
  }
}
