import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import handler from '../api/auth.js';
import config from '../aleph.config.json' with { type: 'json' };

const host = new URL(config.publicAppUrl).host;
const id = randomUUID();
const secret = `fixture_${randomUUID()}`;
const refresh = randomUUID();
const token = [Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url'),
  Buffer.from(JSON.stringify({ sub: id, exp: Math.floor(Date.now() / 1000) + 3600 })).toString('base64url'),
  Buffer.from(randomUUID()).toString('base64url')].join('.');
const credentials = { email: ['fixture', 'example.test'].join('@'), password: randomUUID() };
const session = () => ({ access_token: token, refresh_token: refresh, token_type: 'bearer',
  expires_in: 3600, user: { id, role: 'authenticated', private_field: 'must-not-return' } });
function capture() {
  return { headers: {}, setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    status(c) { this.code = c; return this; }, json(b) { this.body = b; return this; } };
}
function request(method, extras = {}) {
  return { method, body: credentials, headers: { host, origin: config.publicAppUrl,
    'content-type': 'application/json', ...extras } };
}
async function configured(action) {
  const previousFetch = globalThis.fetch;
  const previousUrl = process.env.SUPABASE_URL;
  const previousKey = process.env.SUPABASE_SECRET_KEY;
  process.env.SUPABASE_URL = new URL(config.identityProvider.issuer).origin;
  process.env.SUPABASE_SECRET_KEY = secret;
  try { await action(); } finally {
    globalThis.fetch = previousFetch;
    for (const [name, value] of [['SUPABASE_URL', previousUrl], ['SUPABASE_SECRET_KEY', previousKey]]) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  }
}

test('server Auth logs in without exposing its key, refresh token or user private fields', async () => {
  await configured(async () => {
    globalThis.fetch = async (input, options) => {
      const url = new URL(input);
      assert.equal(url.pathname, '/auth/v1/token');
      assert.equal(url.searchParams.get('grant_type'), 'password');
      assert.equal(new Headers(options.headers).get('apikey'), secret);
      assert.deepEqual(JSON.parse(options.body), { ...credentials, gotrue_meta_security: {} });
      return new Response(JSON.stringify(session()));
    };
    const res = capture();
    await handler(request('POST'), res);
    assert.equal(res.code, 200);
    assert.deepEqual(res.body.session.user, { id });
    assert.equal(res.body.session.access_token, token);
    assert.equal(Object.hasOwn(res.body.session, 'refresh_token'), false);
    assert.match(res.headers['set-cookie'], /HttpOnly; SameSite=Strict; Secure/u);
    assert.equal(res.headers['cache-control'], 'no-store');
    assert.ok(!JSON.stringify(res.body).includes(secret));
  });
});

test('Auth reload refreshes only its HttpOnly cookie and anonymous reload makes no upstream request', async () => {
  await configured(async () => {
    let calls = 0;
    globalThis.fetch = async (input, options) => {
      calls++;
      assert.equal(new URL(input).searchParams.get('grant_type'), 'refresh_token');
      assert.deepEqual(JSON.parse(options.body), { refresh_token: refresh });
      return new Response(JSON.stringify(session()));
    };
    const anonymous = capture();
    await handler(request('GET'), anonymous);
    assert.deepEqual(anonymous.body, { session: null });
    assert.equal(calls, 0);
    const res = capture();
    await handler(request('GET', { cookie: `aleph_refresh=${refresh}` }), res);
    assert.equal(res.code, 200);
    assert.equal(calls, 1);
    assert.equal(res.body.session.user.id, id);
    assert.match(res.headers['set-cookie'], /HttpOnly/u);
  });
});

test('Auth logout revokes only the supplied session and removes its cookie', async () => {
  await configured(async () => {
    globalThis.fetch = async (input, options) => {
      const url = new URL(input);
      assert.equal(url.pathname, '/auth/v1/logout');
      assert.equal(url.searchParams.get('scope'), 'local');
      assert.equal(new Headers(options.headers).get('authorization'), `Bearer ${token}`);
      return new Response(null, { status: 204 });
    };
    const res = capture();
    await handler(request('DELETE', { authorization: `Bearer ${token}` }), res);
    assert.equal(res.code, 200);
    assert.deepEqual(res.body, { session: null });
    assert.match(res.headers['set-cookie'], /Max-Age=0/u);
  });
});

test('Auth denies cross-site, unsupported and malformed requests without contacting Supabase', async () => {
  await configured(async () => {
    globalThis.fetch = async () => { throw new Error('Unexpected upstream request'); };
    for (const [req, status] of [[request('POST', { origin: 'https://untrusted.test' }), 403],
      [request('POST', { origin: undefined }), 403], [request('GET', { 'sec-fetch-site': 'cross-site' }), 403],
      [request('PUT'), 405], [request('POST', { 'content-type': 'text/plain' }), 400]]) {
      const res = capture(); await handler(req, res); assert.equal(res.code, status);
    }
    delete process.env.SUPABASE_SECRET_KEY;
    const res = capture(); await handler(request('POST'), res);
    assert.equal(res.code, 503);
    assert.deepEqual(res.body, { error: 'AUTH_NOT_CONFIGURED' });
  });
});

test('Auth failures hide upstream credentials and clear an invalid refresh session', async () => {
  await configured(async () => {
    globalThis.fetch = async () => new Response(JSON.stringify({ code: 'invalid_credentials',
      message: `${secret} ${credentials.password}` }), { status: 400 });
    const res = capture(); await handler(request('POST'), res);
    assert.equal(res.code, 401);
    assert.deepEqual(res.body, { error: 'LOGIN_FAILED', code: 'invalid_credentials' });
    const expired = capture();
    await handler(request('GET', { cookie: `aleph_refresh=${refresh}` }), expired);
    assert.equal(expired.code, 401);
    assert.match(expired.headers['set-cookie'], /Max-Age=0/u);
  });
});

test('screen has no Supabase key, SDK, direct Auth call or browser token storage', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.doesNotMatch(html, /sb_publishable_|supabase-js|createClient|\.auth\.|localStorage|sessionStorage/u);
  assert.match(html, /fetch\('\/api\/auth'/u);
});
