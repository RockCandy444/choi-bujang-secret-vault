import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';
import { RESOURCE_IDS, RESOURCE_ID_HEADER } from '../src/resource-ids.mjs';
import { denyApi } from '../src/api-denial.mjs';
import { callNoteRecovery, isJudgeB, NOTE_UUID } from '../src/note-recovery.mjs';

let verifyLoginAuthorization;

export default async function handler(request, response) {
  const reject = (status, reason) => denyApi(response, RESOURCE_IDS.notes, status, reason);
  response.setHeader(RESOURCE_ID_HEADER, RESOURCE_IDS.notes);
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Vercel-CDN-Cache-Control', 'no-store');
  response.setHeader('Vary', 'Authorization');
  try {
    const url = new URL(request.url || '/api/restore', 'https://route.invalid');
    if (!['/api/restore', '/api/restore/'].includes(url.pathname) || url.search) return reject(404, 'NOT_FOUND');
  } catch { return reject(404, 'NOT_FOUND'); }
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return reject(405, 'METHOD_NOT_ALLOWED');
  }
  const authorization = request.headers?.authorization;
  if (typeof authorization !== 'string' || !authorization) return reject(401, 'LOGIN_REQUIRED');
  const secret = process.env.SUPABASE_SECRET_KEY;
  let project;
  try {
    project = new URL(process.env.SUPABASE_URL);
    if (project.protocol !== 'https:' || project.username || project.password || project.search || project.hash
        || project.pathname !== '/' || project.origin !== new URL(config.identityProvider.issuer).origin
        || typeof secret !== 'string' || !secret || /\s/u.test(secret)) throw new Error('invalid_config');
    verifyLoginAuthorization ??= createLoginVerifier({ config, supabaseSecretKey: secret });
  } catch { return reject(503, 'NOTE_RECOVERY_NOT_CONFIGURED'); }
  let login;
  try { login = await verifyLoginAuthorization(authorization); }
  catch { return reject(401, 'LOGIN_REQUIRED'); }
  if (!login) return reject(401, 'LOGIN_REQUIRED');
  if (!isJudgeB(login)) return reject(403, 'TEST_B_REQUIRED');
  let id;
  try {
    if ((typeof request.body === 'string' || Buffer.isBuffer(request.body))
        && Buffer.byteLength(request.body) > 256) throw new Error('invalid_body');
    const input = typeof request.body === 'string' || Buffer.isBuffer(request.body)
      ? JSON.parse(request.body.toString()) : request.body;
    if (!input || Array.isArray(input) || Object.keys(input).join(',') !== 'id'
        || typeof input.id !== 'string' || !NOTE_UUID.test(input.id)) throw new Error('invalid_body');
    id = input.id.toLowerCase();
  } catch { return reject(400, 'INVALID_RESTORE_REQUEST'); }
  const restored = await callNoteRecovery({ operation: 'restore', login, id, project, secret });
  if (restored.error) return reject(restored.status, restored.error);
  return response.status(200).json({ ...restored.result, restored: true });
}
