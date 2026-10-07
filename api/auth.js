import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const COOKIE = 'aleph_refresh';
const SAFE_CODES = new Set(['invalid_credentials', 'email_not_confirmed',
  'email_provider_disabled', 'over_request_rate_limit', 'user_banned']);

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Vercel-CDN-Cache-Control', 'no-store');
  response.setHeader('Vary', 'Cookie, Origin');
  const headers = request.headers ?? {};
  const host = headers.host;
  const local = typeof host === 'string' && /^(localhost|127\.0\.0\.1)(:\d+)?$/u.test(host);
  const setCookie = (value = '') => response.setHeader('Set-Cookie',
    `${COOKIE}=${encodeURIComponent(value)}; Path=/api/auth; HttpOnly; SameSite=Strict${local ? '' : '; Secure'}; Max-Age=${value ? 2592000 : 0}`);
  if (!['GET', 'POST', 'DELETE'].includes(request.method)) {
    response.setHeader('Allow', 'GET, POST, DELETE');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  let sameOrigin = false;
  try {
    const origin = new URL(headers.origin);
    sameOrigin = origin.host === host && origin.pathname === '/'
      && !origin.username && !origin.password && !origin.search && !origin.hash
      && origin.protocol === (local ? 'http:' : 'https:');
  } catch { /* Requests without Origin can only read their same-site cookie. */ }
  if (headers['sec-fetch-site'] === 'cross-site'
      || (headers.origin && !sameOrigin)
      || (request.method !== 'GET' && !sameOrigin)) {
    return response.status(403).json({ error: 'AUTH_ORIGIN_DENIED' });
  }
  let refresh;
  try {
    const cookies = (headers.cookie ?? '').split(';').map(s => s.trim())
      .filter(s => s.startsWith(`${COOKIE}=`));
    if (cookies.length === 1) refresh = decodeURIComponent(cookies[0].slice(COOKIE.length + 1));
    if (refresh && (refresh.length > 2048 || !/^[A-Za-z0-9._-]+$/u.test(refresh))) refresh = undefined;
  } catch { /* Malformed cookies are unauthenticated. */ }
  if (request.method === 'GET' && !refresh) {
    return response.status(200).json({ session: null });
  }
  let credentials;
  if (request.method === 'POST') {
    try {
      if (!/^application\/json(?:;|$)/iu.test(headers['content-type'] ?? '')) throw new Error();
      if (typeof request.body === 'string' && request.body.length > 4096) throw new Error();
      const input = typeof request.body === 'string' || Buffer.isBuffer(request.body)
        ? JSON.parse(request.body.toString()) : request.body;
      if (!input || Array.isArray(input) || typeof input.email !== 'string'
          || input.email.length > 320 || !input.email.trim()
          || typeof input.password !== 'string' || !input.password || input.password.length > 1024) throw new Error();
      credentials = { email: input.email.trim(), password: input.password };
    } catch { return response.status(400).json({ error: 'INVALID_LOGIN_INPUT' }); }
  }
  let project;
  const key = process.env.SUPABASE_SECRET_KEY;
  try {
    project = new URL(process.env.SUPABASE_URL);
    if (project.protocol !== 'https:' || project.username || project.password
        || project.search || project.hash || project.pathname !== '/'
        || project.origin !== new URL(config.identityProvider.issuer).origin
        || typeof key !== 'string' || !key || /\s/u.test(key)) {
      throw new Error();
    }
  } catch { return response.status(503).json({ error: 'AUTH_NOT_CONFIGURED' }); }
  try {
    // Each request gets an isolated client. Never persist credentials or share sessions.
    const client = createClient(project.origin, key, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
      global: { fetch: (input, options) => fetch(input, { ...options,
        redirect: 'error', signal: AbortSignal.timeout(10000), cache: 'no-store' }) },
    });
    if (request.method === 'DELETE') {
      const bearer = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/u.exec(headers.authorization ?? '');
      if (bearer) {
        const { error } = await client.auth.admin.signOut(bearer[1], 'local');
        if (error && ![401, 403, 404].includes(error.status)) {
          return response.status(502).json({ error: 'AUTH_UNAVAILABLE' });
        }
      } else if (refresh) {
        const { data, error } = await client.auth.refreshSession({ refresh_token: refresh });
        if (!error && data.session) {
          const result = await client.auth.admin.signOut(data.session.access_token, 'local');
          if (result.error) return response.status(502).json({ error: 'AUTH_UNAVAILABLE' });
        }
      }
      setCookie();
      return response.status(200).json({ session: null });
    }
    const { data, error } = request.method === 'POST'
      ? await client.auth.signInWithPassword(credentials)
      : await client.auth.refreshSession({ refresh_token: refresh });
    if (error) {
      if (request.method === 'GET') setCookie();
      return response.status(error.status === 429 ? 429 : error.status >= 500 ? 502 : 401)
        .json({ error: 'LOGIN_FAILED', code: SAFE_CODES.has(error.code) ? error.code : 'invalid_credentials' });
    }
    const session = data?.session;
    if (!session || !UUID.test(session.user?.id ?? '') || session.user.role !== 'authenticated'
        || typeof session.access_token !== 'string' || !session.access_token
        || session.access_token.includes(key) || typeof session.refresh_token !== 'string'
        || session.refresh_token.includes(key)
        || !/^[A-Za-z0-9._-]{1,2048}$/u.test(session.refresh_token)
        || !Number.isSafeInteger(session.expires_at)) throw new Error();
    setCookie(session.refresh_token);
    return response.status(200).json({ session: { user: { id: session.user.id },
      access_token: session.access_token, expires_at: session.expires_at } });
  } catch {
    // No upstream messages, passwords, cookies, keys or tokens in logs/errors.
    return response.status(502).json({ error: 'AUTH_UNAVAILABLE' });
  }
}
