import { randomUUID } from 'node:crypto';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
let verifyLoginAuthorization;

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Vercel-CDN-Cache-Control', 'no-store');
  response.setHeader('Vary', 'Authorization');
  let id;
  try {
    const path = new URL(request.url || '/api/notes', 'https://route.invalid').pathname;
    if (path !== '/api/notes' && path !== '/api/notes/') {
      const match = /^\/api\/notes\/([^/]+)\/?$/u.exec(path);
      if (!match) return response.status(404).json({ error: 'NOT_FOUND' });
      id = decodeURIComponent(match[1]);
      if (!UUID.test(id)) return response.status(400).json({ error: 'INVALID_NOTE_ID' });
      id = id.toLowerCase();
    }
  } catch {
    return response.status(400).json({ error: 'INVALID_NOTE_ID' });
  }
  const methods = id ? ['GET', 'PUT', 'DELETE'] : ['GET', 'POST'];
  if (!methods.includes(request.method)) {
    response.setHeader('Allow', methods.join(', '));
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const authorization = request.headers?.authorization;
  if (typeof authorization !== 'string' || !authorization) {
    return response.status(401).json({ error: 'LOGIN_REQUIRED' });
  }

  const secret = process.env.SUPABASE_SECRET_KEY;
  let endpoint;
  try {
    const project = new URL(process.env.SUPABASE_URL);
    if (project.protocol !== 'https:' || project.username || project.password
        || project.search || project.hash || project.pathname !== '/'
        || project.origin !== new URL(config.identityProvider.issuer).origin
        || !secret || /\s/u.test(secret)) throw new Error('Invalid server configuration');
    endpoint = new URL('/rest/v1/notes', project);
    verifyLoginAuthorization ??= createLoginVerifier({ config, supabaseSecretKey: secret });
  } catch {
    return response.status(503).json({ error: 'NOTES_NOT_CONFIGURED' });
  }

  let login;
  try {
    // Only the existing verifier establishes identity. Ignore client userId/role.
    login = await verifyLoginAuthorization(authorization);
    if (!login) {
      return response.status(401).json({ error: 'LOGIN_REQUIRED' });
    }
  } catch {
    return response.status(401).json({ error: 'LOGIN_REQUIRED' });
  }

  let payload;
  if (request.method === 'POST' || request.method === 'PUT') {
    try {
      const input = typeof request.body === 'string' || Buffer.isBuffer(request.body)
        ? JSON.parse(request.body.toString()) : request.body;
      if (!input || Array.isArray(input) || typeof input.title !== 'string'
          || !input.title.trim() || input.title.length > 200
          || typeof input.body !== 'string' || input.body.length > 20000) {
        throw new Error('Invalid note');
      }
      payload = { title: input.title.trim(), content: input.body };
      if (request.method === 'POST') {
        if (input.id !== undefined && (typeof input.id !== 'string' || !UUID.test(input.id))) {
          return response.status(400).json({ error: 'INVALID_NOTE_ID' });
        }
        id = input.id?.toLowerCase() ?? randomUUID();
        payload.id = id;
        payload.owner_id = login.userId;
      }
      // Never accept owner_id, userId or role from the request body.
    } catch {
      return response.status(400).json({ error: 'INVALID_NOTE' });
    }
  }
  endpoint.searchParams.set('select', 'id,title,content');
  if (request.method !== 'POST' && id) {
    endpoint.searchParams.set('id', `eq.${id}`);
    // Stage 3 intentionally has no owner check for individual notes.
    // Stage 4 will restrict item GET, PUT and DELETE to the verified owner.
  } else if (request.method === 'GET') {
    endpoint.searchParams.set('owner_id', `eq.${login.userId}`);
    endpoint.searchParams.set('order', 'created_at.asc,id.asc');
  }

  try {
    const headers = { apikey: secret, Accept: 'application/json' };
    if (request.method !== 'GET') headers.Prefer = 'return=representation';
    if (payload) headers['Content-Type'] = 'application/json';
    const upstream = await fetch(endpoint, {
      method: request.method === 'PUT' ? 'PATCH' : request.method,
      headers, ...(payload ? { body: JSON.stringify(payload) } : {}),
      redirect: 'error', signal: AbortSignal.timeout(10000), cache: 'no-store',
    });
    if (request.method === 'POST' && upstream.status === 409) {
      return response.status(409).json({ error: 'NOTE_ALREADY_EXISTS' });
    }
    if (!upstream.ok) throw new Error('Upstream failure');
    const rows = await upstream.json();
    if (!Array.isArray(rows) || (id && rows.length > 1) || rows.some(row => !row
        || typeof row.id !== 'string' || !UUID.test(row.id)
        || (id && row.id.toLowerCase() !== id)
        || typeof row.title !== 'string' || typeof row.content !== 'string'
        || row.title.includes(secret) || row.content.includes(secret))) {
      throw new Error('Invalid notes response');
    }
    if (id && rows.length === 0) {
      if (request.method === 'POST') throw new Error('Missing created note');
      return response.status(404).json({ error: 'NOTE_NOT_FOUND' });
    }
    if (request.method === 'POST' || request.method === 'DELETE') {
      return response.status(request.method === 'POST' ? 201 : 200).json({ id });
    }
    const notes = rows.map(row => ({ id: row.id.toLowerCase(), title: row.title, body: row.content }));
    return response.status(200).json(id ? notes[0] : notes);
  } catch {
    // Do not log the exception: it may contain an upstream URL or credential.
    return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
  }
}
