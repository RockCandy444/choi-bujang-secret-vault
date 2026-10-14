import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import handler from '../api/notes.js';
import itemHandler from '../api/notes/[id].js';
import ownListHandler from '../api/my/notes.js';
import noticesHandler from '../api/notices.js';

const config = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));
// Synthetic credentials exist only in test memory; no real accounts or keys.
const signingKeys = await generateKeyPair('ES256');
const kid = randomUUID();
const publicJwk = { ...await exportJWK(signingKeys.publicKey), kid, alg: 'ES256' };
const subject = randomUUID();
async function authorization(overrides = {}, privateKey = signingKeys.privateKey) {
  const now = Math.floor(Date.now() / 1000);
  return `Bearer ${await new SignJWT({ iss: config.identityProvider.issuer,
    aud: config.identityProvider.audience, role: 'authenticated', sub: subject,
    iat: now, exp: now + 300, ...overrides }).setProtectedHeader({ alg: 'ES256', kid }).sign(privateKey)}`;
}

function mockUpstream(notesResponse, adminResponse) {
  globalThis.fetch = async (input, options) => {
    const url = new URL(input);
    if (url.href === config.identityProvider.jwksUrl) {
      return new Response(JSON.stringify({ keys: [publicJwk] }));
    }
    // An unknown key or symmetric token must be rejected by the simulated Auth server.
    if (url.pathname === '/auth/v1/user') {
      return new Response(JSON.stringify({ code: 'bad_jwt', msg: 'Rejected' }), { status: 401 });
    }
    assert.equal(url.origin, new URL(config.identityProvider.issuer).origin);
    if (adminResponse && url.pathname.startsWith('/auth/v1/admin/users/')) {
      return adminResponse(url, options);
    }
    assert.equal(url.pathname, '/rest/v1/notes');
    return notesResponse(url, options);
  };
}

const key = 'test-server-only-credential';
const rows = Array.from({ length: 4 }, (_, index) => ({ id: randomUUID(), title: `DB title ${index + 1}`,
  content: `DB content ${index + 1}` }));

function responseCapture() {
  return {
    headers: {}, code: undefined, body: undefined,
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    status(code) { this.code = code; return this; },
    json(body) { this.body = body; return this; },
  };
}

async function configured(work) {
  const originalFetch = globalThis.fetch;
  const originalUrl = process.env.SUPABASE_URL;
  const originalKey = process.env.SUPABASE_SECRET_KEY;
  const originalWarn = console.warn;
  console.warn = () => {};
  process.env.SUPABASE_URL = new URL(config.identityProvider.issuer).origin;
  process.env.SUPABASE_SECRET_KEY = key;
  try { await work(); }
  finally {
    console.warn = originalWarn;
    globalThis.fetch = originalFetch;
    if (originalUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = originalUrl;
    if (originalKey === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = originalKey;
  }
}

test('verified A GET reads four DB notes with a server-only apikey and strips extra fields', async () => {
  await configured(async () => {
    mockUpstream(async (url, options) => {
      assert.equal(url.origin, process.env.SUPABASE_URL);
      assert.equal(url.pathname, '/rest/v1/notes');
      assert.equal(url.searchParams.get('select'), 'id,title,content,owner_id');
      assert.equal(url.searchParams.get('owner_id'), `eq.${subject}`);
      assert.equal(url.searchParams.has('limit'), false);
      assert.equal(options.headers.apikey, key);
      assert.equal(options.headers.Authorization, undefined);
      assert.equal(options.redirect, 'error');
      assert.ok(options.signal instanceof AbortSignal);
      return new Response(JSON.stringify(rows.map(row => ({ ...row, internal_key: key, owner_id: subject }))));
    });
    const response = responseCapture();
    // Client input must not replace the configured DB URL or server credential.
    await handler({ method: 'GET', headers: { authorization: await authorization() },
      query: { url: 'https://untrusted.example', key: 'untrusted', userId: 'untrusted', role: 'service_role' } }, response);
    assert.equal(response.code, 200);
    assert.deepEqual(response.body, rows.map(({ id, title, content }) => ({ id, title, body: content })));
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.equal(response.headers['x-aleph-resource-id'], 'notes');
    assert.equal(response.headers['vercel-cdn-cache-control'], 'no-store');
    assert.ok(!JSON.stringify(response).includes(key));
  });
});

test('missing or unsafe configuration fails without fetching or leaking values', async () => {
  const userInfoUrl = new URL(new URL(config.identityProvider.issuer).origin);
  userInfoUrl.username = 'synthetic';
  userInfoUrl.password = 'not-a-real-credential';
  await configured(async () => {
    globalThis.fetch = async () => { throw new Error('Must not fetch'); };
    for (const [url, credential] of [
      [new URL(config.identityProvider.issuer).origin, undefined],
      [undefined, key], ['http://learning-example.supabase.co', key],
      [userInfoUrl.href, key],
      ['https://learning-example.supabase.co/?apikey=anything', key],
      ['https://another-project.supabase.co', key],
    ]) {
      if (url === undefined) delete process.env.SUPABASE_URL;
      else process.env.SUPABASE_URL = url;
      if (credential === undefined) delete process.env.SUPABASE_SECRET_KEY;
      else process.env.SUPABASE_SECRET_KEY = credential;
      const response = responseCapture();
      await handler({ method: 'GET', headers: { authorization: await authorization() } }, response);
      assert.equal(response.code, 503);
      assert.deepEqual(response.body, { error: 'NOTES_NOT_CONFIGURED' });
    }
  });
});

test('upstream errors, malformed data, and unexpected credential content are never echoed or logged', async () => {
  await configured(async () => {
    const savedConsole = { log: console.log, error: console.error, warn: console.warn };
    const logs = [];
    for (const method of Object.keys(savedConsole)) console[method] = (...args) => logs.push(args);
    try {
      for (const result of [
        () => new Response(key, { status: 403 }),
        () => new Response(key),
        () => new Response(JSON.stringify({ error: key })),
        () => new Response(JSON.stringify([{ title: 'invalid', content: key }])),
        () => { throw new Error(`network failure: ${key}`); },
      ]) {
        mockUpstream(async () => result());
        const response = responseCapture();
        await handler({ method: 'GET', headers: { authorization: await authorization() } }, response);
        assert.equal(response.code, 502);
        assert.deepEqual(response.body, { error: 'NOTES_UNAVAILABLE' });
        assert.ok(!JSON.stringify(response).includes(key));
      }
      assert.deepEqual(logs.map(args => JSON.parse(args[0])), Array(5).fill({
        event: 'api_denied', resourceId: 'notes', reason: 'NOTES_UNAVAILABLE',
      }));
      assert.ok(!JSON.stringify(logs).includes(key));
    } finally { Object.assign(console, savedConsole); }
  });
});

test('unsupported methods are refused without querying the DB', async () => {
  await configured(async () => {
    globalThis.fetch = async () => { throw new Error('Must not fetch'); };
    const response = responseCapture();
    await handler({ method: 'PATCH' }, response);
    assert.equal(response.code, 405);
    assert.equal(response.headers.allow, 'GET, POST');
  });
});

test('missing, malformed, expired, tampered and wrong issuer/audience/role tokens return 401 without DB reads', async () => {
  await configured(async () => {
    let dbReads = 0;
    mockUpstream(async () => { dbReads++; return new Response(JSON.stringify(rows)); });
    const otherKeys = await generateKeyPair('ES256');
    const cases = [undefined, '', 'Bearer invalid', ['Bearer invalid'],
      await authorization({ exp: Math.floor(Date.now() / 1000) - 1 }),
      await authorization({ iss: 'https://untrusted.example/auth/v1' }),
      await authorization({ aud: 'untrusted' }), await authorization({ role: 'service_role' }),
      await authorization({}, otherKeys.privateKey)];
    for (const bearer of cases) {
      const response = responseCapture();
      await handler({ method: 'GET', headers: { authorization: bearer },
        query: { userId: subject, role: 'authenticated' },
        body: { userId: subject, role: 'service_role' } }, response);
      assert.equal(response.code, 401);
      assert.deepEqual(response.body, { error: 'LOGIN_REQUIRED' });
    }
    assert.equal(dbReads, 0);
  });
});

async function mountPage(browserFetch, initialSession = null, deviceFetch = async () =>
  new Response(JSON.stringify({ approved: true, reason: 'fixture_registered' }))) {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.ok(!html.includes('SUPABASE_SECRET_KEY'));
  const script = html.match(/<script type="module">([\s\S]*?)<\/script>/u)[1];
  const elements = new Map();
  function element(tag) {
    return { tag, value: '', textContent: '', children: [], hidden: false, listeners: {},
      append(...children) { this.children.push(...children); },
      replaceChildren(...children) { this.children = children; },
      addEventListener(event, callback) { this.listeners[event] = callback; },
      setAttribute() {}, focus() {}, set innerHTML(_) { throw new Error('Use textContent'); } };
  }
  const document = { createElement: element, querySelector(id) {
    if (!elements.has(id)) elements.set(id, element('test'));
    return elements.get(id);
  } };
  let authSession = initialSession;
  const events = {};
  const browserGlobal = { setTimeout() { return 0; }, clearTimeout() {},
    addEventListener(event, callback) { events[event] = callback; } };
  const authFetch = async (path, options) => {
    // Local server-status fixture only; never represents an approved live device.
    if (path.startsWith('/api/device/')) return deviceFetch(path, options);
    if (path !== '/api/auth') return browserFetch(path, options);
    if (options.method === 'DELETE') authSession = null;
    return new Response(JSON.stringify({ session: authSession ? { ...authSession,
      expires_at: Math.floor(Date.now() / 1000) + 3600 } : null }));
  };
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  await new AsyncFunction('document', 'fetch', 'globalThis', script)(document, authFetch, browserGlobal);
  await new Promise(setImmediate);
  const changeSession = (event, session) => {
    authSession = session;
    if (event === 'SIGNED_OUT') return elements.get('#logout-button').listeners.click();
    if (event === 'TOKEN_REFRESHED') return events.focus();
    return elements.get('#login-form').listeners.submit({ preventDefault() {} });
  };
  return { elements, changeSession };
}

test('page makes no anonymous read, sends only the server-issued token, renders text, and clears notes on logout', async () => {
  let requests = 0;
  const token = (await authorization()).slice('Bearer '.length);
  const suppliedRows = rows.map(row => ({ ...row, title: `<img onerror=alert(1)>${row.title}` }));
  const page = await mountPage(async (path, options) => {
    requests++;
    assert.equal(path, '/api/my/notes');
    assert.equal(options.cache, 'no-store');
    assert.deepEqual(Object.keys(options.headers), ['Authorization']);
    assert.ok(options.headers.Authorization === `Bearer ${token}`);
    return new Response(JSON.stringify(suppliedRows.map(({ id, title, content }) => ({ id, title, body: content }))));
  });
  const list = page.elements.get('#notes');
  assert.equal(requests, 0);
  assert.match(list.children[0].textContent, /로그인 후/u);
  const session = { user: { id: subject }, access_token: token };
  await page.changeSession('SIGNED_IN', session);
  await new Promise(setImmediate);
  assert.equal(list.children.length, 4);
  assert.deepEqual(list.children.map(card => card.children.slice(0, 2).map(child => child.textContent)),
    suppliedRows.map(row => [row.title, row.content]));
  await page.changeSession('TOKEN_REFRESHED', session);
  await new Promise(setImmediate);
  assert.equal(requests, 2);
  page.changeSession('SIGNED_OUT', null);
  assert.equal(list.children.length, 1);
  assert.match(list.children[0].textContent, /로그인 후/u);
  assert.equal(page.elements.get('#login-form').hidden, false);
});

test('device pending, unavailable or malformed status cannot request or display protected notes', async () => {
  const session = { user: { id: subject }, access_token: (await authorization()).slice(7) };
  for (const [code, state] of [[200, { approved: false, reason: 'device_not_registered' }],
    [503, { approved: false, error: 'DEVICE_APPROVAL_NOT_CONFIGURED' }],
    [200, { approved: 'true', reason: 'untrusted' }], [200, { approved: true, reason: 'untrusted', extra: true }]]) {
    let notesRequested = 0;
    const page = await mountPage(async () => { notesRequested++; throw new Error('No notes before approval'); }, session,
      async () => new Response(JSON.stringify(state), { status: code }));
    assert.equal(notesRequested, 0);
    assert.equal(page.elements.get('#note-editor').hidden, true);
    assert.match(page.elements.get('#notes').children[0].textContent, /기기 승인 전/u);
    assert.equal(page.elements.get('#note-save').disabled, true);
    await page.elements.get('#note-form').listeners.submit({ preventDefault() {} });
    assert.equal(notesRequested, 0);
  }
});

test('approval request receipt cannot open notes without a separate approved status', async () => {
  const session = { user: { id: subject }, access_token: (await authorization()).slice(7) };
  const paths = [];
  let notesRequested = 0;
  const page = await mountPage(async () => { notesRequested++; throw new Error('No approval'); }, session,
    async (path, options) => {
      paths.push(path);
      assert.equal(options.cache, 'no-store');
      return new Response(JSON.stringify({ approved: path.endsWith('request'), reason: 'fixture' }),
        { status: path.endsWith('request') ? 202 : 200 });
    });
  page.elements.get('#device-request').listeners.click();
  await new Promise(setImmediate);
  assert.deepEqual(paths, ['/api/device/status', '/api/device/request', '/api/device/status']);
  assert.equal(notesRequested, 0);
  assert.equal(page.elements.get('#note-editor').hidden, true);
});

test('device recheck closes prior notes and late approval after logout cannot reopen them', async () => {
  const session = { user: { id: subject }, access_token: (await authorization()).slice(7) };
  let finish;
  let calls = 0;
  let noteCalls = 0;
  const page = await mountPage(async () => { noteCalls++; return new Response('[]'); }, session,
    async () => {
      if (++calls === 1) return new Response(JSON.stringify({ approved: true, reason: 'fixture_registered' }));
      return new Promise(resolve => { finish = resolve; });
    });
  assert.equal(noteCalls, 1);
  assert.equal(page.elements.get('#note-editor').hidden, false);
  page.elements.get('#device-check').listeners.click();
  assert.equal(page.elements.get('#note-editor').hidden, true);
  assert.match(page.elements.get('#notes').children[0].textContent, /기기 승인 전/u);
  await page.changeSession('SIGNED_OUT', null);
  finish(new Response(JSON.stringify({ approved: true, reason: 'fixture_registered' })));
  await new Promise(setImmediate);
  assert.equal(noteCalls, 1);
  assert.equal(page.elements.get('#note-editor').hidden, true);
  assert.match(page.elements.get('#notes').children[0].textContent, /로그인 후/u);
});

test('logout discards late note responses, and API rejection displays no notes', async () => {
  let complete;
  let signal;
  const session = { user: { id: subject }, access_token: (await authorization()).slice(7) };
  const page = await mountPage((_path, options) => {
    signal = options.signal;
    return new Promise(resolve => { complete = resolve; });
  }, session);
  page.changeSession('SIGNED_OUT', null);
  assert.equal(signal.aborted, true);
  complete(new Response(JSON.stringify(rows.map(({ id, title, content }) => ({ id, title, body: content })))));
  await new Promise(setImmediate);
  assert.match(page.elements.get('#notes').children[0].textContent, /로그인 후/u);
  const denied = await mountPage(async () => new Response('{}', { status: 401 }), session);
  await new Promise(setImmediate);
  assert.equal(denied.elements.get('#notes').children.length, 1);
  assert.match(denied.elements.get('#notes').children[0].textContent, /로그인 확인에 실패/u);
});

function mockDatabase() {
  const store = new Map(rows.map(row => [row.id, { ...row, owner_id: null }]));
  const operations = [];
  mockUpstream(async (url, options) => {
    assert.equal(options.headers.apikey, key);
    assert.equal(options.headers.Authorization, undefined);
    const id = url.searchParams.get('id')?.slice(3);
    const owner = url.searchParams.get('owner_id')?.slice(3);
    operations.push({ method: options.method, id, owner });
    if (options.method !== 'GET') assert.equal(options.headers.Prefer, 'return=representation');
    if (options.method === 'POST') {
      const input = JSON.parse(options.body);
      if (store.has(input.id)) return new Response('{}', { status: 409 });
      store.set(input.id, input);
      return new Response(JSON.stringify([input]), { status: 201 });
    }
    const selected = [...store.values()].filter(row => (!id || row.id === id)
      && (!owner || row.owner_id === owner));
    if (options.method === 'PATCH') {
      const input = JSON.parse(options.body);
      assert.deepEqual(Object.keys(input).sort(), ['content', 'title']);
      for (const row of selected) Object.assign(row, input);
    }
    if (options.method === 'DELETE') for (const row of selected) store.delete(row.id);
    return new Response(JSON.stringify(selected));
  });
  return { store, operations };
}

test('A creates, lists, reads, updates and deletes UUID notes with server-assigned ownership', async () => {
  await configured(async () => {
    const { store, operations } = mockDatabase();
    const bearer = await authorization();
    async function send(method, path, body, query = {}) {
      const response = responseCapture();
      await (path === '/api/notes' ? handler : itemHandler)({ method, url: path,
        headers: { authorization: bearer }, body, query }, response);
      return response;
    }
    const initial = await send('GET', '/api/notes');
    assert.deepEqual(initial.body, []);
    const created = await send('POST', '/api/notes', { title: 'Synthetic created title', body: 'Synthetic body',
      owner_id: randomUUID(), userId: 'untrusted', role: 'service_role' });
    assert.equal(created.code, 201);
    assert.deepEqual(Object.keys(created.body), ['id']);
    const id = created.body.id;
    assert.match(id, /^[0-9a-f-]{36}$/u);
    assert.equal(store.get(id).owner_id, subject);
    assert.equal(store.get(id).content, 'Synthetic body');
    const suppliedId = randomUUID();
    assert.equal((await send('POST', '/api/notes', JSON.stringify({ id: suppliedId,
      title: 'Synthetic supplied ID', body: '' }))).body.id, suppliedId);
    const duplicate = await send('POST', '/api/notes', { id, title: 'Must not overwrite', body: '' });
    assert.equal(duplicate.code, 409);
    const listing = await send('GET', '/api/notes', undefined, { owner_id: 'untrusted', userId: 'untrusted' });
    assert.equal(listing.body.length, 2);
    assert.ok(listing.body.some(note => note.id === id));
    const fetched = await send('GET', `/api/notes/${id}?id=${suppliedId}`, undefined, { id: suppliedId });
    assert.deepEqual(fetched.body, { id, title: 'Synthetic created title', body: 'Synthetic body' });
    const updated = await send('PUT', `/api/notes/${id}`, {
      title: 'Synthetic updated title', body: 'Synthetic updated body' });
    assert.deepEqual(updated.body, { id, title: 'Synthetic updated title', body: 'Synthetic updated body' });
    assert.equal(store.get(id).owner_id, subject);
    assert.equal((await send('DELETE', `/api/notes/${id}`)).code, 200);
    assert.equal((await send('GET', `/api/notes/${id}`)).code, 404);
    assert.equal((await send('PUT', `/api/notes/${id}`, { title: 'Missing', body: '' })).code, 404);
    assert.equal((await send('DELETE', `/api/notes/${id}`)).code, 404);
    assert.ok(operations.filter(op => op.method !== 'POST').every(op => op.owner === subject));
    for (const row of rows) assert.deepEqual(store.get(row.id), { ...row, owner_id: null });
    assert.deepEqual(config.allowedRoutes, ['GET /api/my/notes', 'POST /api/notes',
      'GET /api/notes/:id', 'PUT /api/notes/:id', 'DELETE /api/notes/:id', 'GET /api/notices', 'POST /api/restore']);
  });
});

test('A and B keep their own CRUD and cannot access each other or unowned notes', async () => {
  await configured(async () => {
    const { store, operations } = mockDatabase();
    const otherSubject = randomUUID();
    for (const row of rows.slice(0, 3)) store.get(row.id).owner_id = subject;
    store.get(rows[3].id).owner_id = otherSubject;
    const unowned = { id: randomUUID(), owner_id: null, title: 'Unowned synthetic title', content: '' };
    store.set(unowned.id, unowned);

    for (const [userId, ownId, foreignId] of [
      [subject, rows[0].id, rows[3].id],
      [otherSubject, rows[3].id, rows[0].id],
    ]) {
      const bearer = await authorization({ sub: userId });
      const start = operations.length;
      async function send(method, path, body) {
        const response = responseCapture();
        await itemHandler({ method, url: path, headers: { authorization: bearer }, body,
          query: { owner_id: store.get(foreignId).owner_id, userId: store.get(foreignId).owner_id } }, response);
        return response;
      }
      const listing = await send('GET', `/api/notes?owner_id=${store.get(foreignId).owner_id}`);
      assert.equal(listing.code, 200);
      assert.ok(listing.body.some(note => note.id === ownId));
      assert.ok(!listing.body.some(note => [foreignId, unowned.id].includes(note.id)));
      for (const note of listing.body) {
        assert.equal(store.get(note.id).owner_id, userId);
        assert.deepEqual(Object.keys(note).sort(), ['body', 'id', 'title']);
      }
      const own = await send('GET', `/api/notes/${ownId}`);
      assert.deepEqual(own.body, { id: ownId, title: store.get(ownId).title, body: store.get(ownId).content });

      for (const deniedId of [foreignId, unowned.id, randomUUID()]) {
        const before = structuredClone(store.get(deniedId));
        for (const method of ['GET', 'PUT', 'DELETE']) {
          const denied = await send(method, `/api/notes/${deniedId}?owner_id=${userId}&id=${ownId}`,
            { title: 'Must not change', body: 'Must not change', userId, role: 'service_role' });
          assert.equal(denied.code, 404);
          assert.deepEqual(denied.body, { error: 'NOTE_NOT_FOUND' });
          assert.deepEqual(store.get(deniedId), before);
        }
      }
      const collision = await send('POST', '/api/notes', { id: foreignId, title: 'Must not replace', body: '' });
      assert.equal(collision.code, 409);
      const created = await send('POST', `/api/notes?owner_id=${store.get(foreignId).owner_id}`, {
        title: 'Synthetic owner test', body: 'Synthetic body', owner_id: store.get(foreignId).owner_id,
        userId: store.get(foreignId).owner_id, role: 'service_role',
      });
      assert.equal(created.code, 201);
      assert.equal(store.get(created.body.id).owner_id, userId);
      const updated = await send('PUT', `/api/notes/${created.body.id}?owner_id=${store.get(foreignId).owner_id}`, {
        title: 'Synthetic edited title', body: 'Synthetic edited body',
      });
      assert.equal(updated.code, 200);
      assert.deepEqual(updated.body, { id: created.body.id, title: 'Synthetic edited title', body: 'Synthetic edited body' });
      assert.equal(store.get(created.body.id).owner_id, userId);
      assert.equal((await send('DELETE', `/api/notes/${created.body.id}`)).code, 200);
      assert.equal(store.has(created.body.id), false);
      assert.ok(operations.slice(start).filter(op => op.method !== 'POST').every(op => op.owner === userId));
    }
    assert.deepEqual(store.get(unowned.id), unowned);
  });
});

test('PUT rejects owner_id fields before DB access and preserves the existing owner and contents', async () => {
  await configured(async () => {
    const { store, operations } = mockDatabase();
    const id = rows[0].id;
    store.get(id).owner_id = subject;
    const before = structuredClone(store.get(id));
    const bearer = await authorization();
    for (const owner_id of [randomUUID(), subject, null]) {
      const response = responseCapture();
      await handler({ method: 'PUT', url: `/api/notes/${id}`, headers: { authorization: bearer },
        body: { title: 'Must not change', body: 'Must not change', owner_id } }, response);
      assert.equal(response.code, 400);
      assert.deepEqual(response.body, { error: 'OWNER_CHANGE_NOT_ALLOWED' });
      assert.deepEqual(store.get(id), before);
    }
    assert.equal(operations.length, 0);
  });
});

test('all CRUD responses fail closed if the DB returns a row with a foreign, null or missing owner', async () => {
  await configured(async () => {
    const bearer = await authorization();
    const id = rows[0].id;
    for (const owner_id of [randomUUID(), null, undefined]) {
      mockUpstream(async () => new Response(JSON.stringify([{ ...rows[0], owner_id }])));
      for (const [method, path] of [['GET', '/api/notes'], ['GET', `/api/notes/${id}`],
        ['POST', '/api/notes'], ['PUT', `/api/notes/${id}`], ['DELETE', `/api/notes/${id}`]]) {
        const response = responseCapture();
        await handler({ method, url: path, headers: { authorization: bearer },
          body: { id, title: 'Synthetic title', body: '' } }, response);
        assert.equal(response.code, 502);
        assert.deepEqual(response.body, { error: 'NOTES_UNAVAILABLE' });
      }
    }
  });
});

test('all CRUD routes reject missing or invalid login before reading or writing DB data', async () => {
  await configured(async () => {
    let requests = 0;
    globalThis.fetch = async () => { requests++; throw new Error('Must not access DB'); };
    const id = randomUUID();
    for (const [method, path] of [['GET', '/api/notes'], ['POST', '/api/notes'],
      ['GET', `/api/notes/${id}`], ['PUT', `/api/notes/${id}`], ['DELETE', `/api/notes/${id}`]]) {
      for (const bearer of [undefined, 'Bearer invalid']) {
        const response = responseCapture();
        await handler({ method, url: path, headers: { authorization: bearer },
          body: { title: 'Synthetic title', body: '', userId: subject, role: 'authenticated' } }, response);
        assert.equal(response.code, 401);
        assert.deepEqual(response.body, { error: 'LOGIN_REQUIRED' });
      }
    }
    assert.equal(requests, 0);
  });
});

test('invalid note IDs and payloads are rejected without DB mutations', async () => {
  await configured(async () => {
    const { operations } = mockDatabase();
    const bearer = await authorization();
    const id = randomUUID();
    for (const [method, path, body] of [['POST', '/api/notes', '{'],
      ['POST', '/api/notes', { id: 'not-a-uuid', title: 'Synthetic', body: '' }],
      ['POST', '/api/notes', { title: '', body: '' }],
      ['PUT', `/api/notes/${id}`, { title: 'Synthetic', body: 7 }],
      ['GET', '/api/notes/not-a-uuid', undefined]]) {
      const response = responseCapture();
      await handler({ method, url: path, headers: { authorization: bearer }, body }, response);
      assert.equal(response.code, 400);
    }
    assert.equal(operations.length, 0);
  });
});

test('A can create, edit and delete through the browser UI while remaining logged in', async () => {
  await configured(async () => {
    const { store } = mockDatabase();
    const bearer = await authorization();
    const page = await mountPage(async (path, options) => {
      const response = responseCapture();
      await handler({ method: options.method ?? 'GET', url: path,
        headers: { authorization: options.headers.Authorization }, body: options.body }, response);
      return new Response(JSON.stringify(response.body), { status: response.code });
    }, { user: { id: subject }, access_token: bearer.slice(7) });
    const get = id => page.elements.get('#' + id);
    get('note-title').value = 'Synthetic UI title';
    get('note-body').value = 'Synthetic UI body';
    await get('note-form').listeners.submit({ preventDefault() {} });
    assert.equal(get('notes').children.length, 1);
    let card = get('notes').children[0];
    assert.equal(card.children[0].textContent, 'Synthetic UI title');
    const created = [...store.values()].find(row => row.owner_id === subject);
    assert.ok(created);
    await card.children[2].children[0].listeners.click();
    assert.equal(get('note-body').value, 'Synthetic UI body');
    get('note-title').value = 'Synthetic UI edited';
    get('note-body').value = 'Synthetic UI changed';
    await get('note-form').listeners.submit({ preventDefault() {} });
    card = get('notes').children[0];
    assert.equal(card.children[1].textContent, 'Synthetic UI changed');
    assert.equal(store.get(created.id).owner_id, subject);
    await card.children[2].children[1].listeners.click();
    assert.equal(store.has(created.id), false);
    assert.match(get('notes').children[0].textContent, /등록된 가상 메모가 없습니다/u);
    assert.equal(get('login-form').hidden, true);
    assert.equal(get('note-editor').hidden, false);
  });
});

test('resource IDs cannot be replaced by client input, including on rejected CRUD requests', async () => {
  const id = randomUUID();
  for (const [method, url, handle] of [
    ['GET', '/api/notes', handler], ['POST', '/api/notes', handler],
    ['GET', `/api/notes/${id}`, itemHandler], ['PUT', `/api/notes/${id}`, itemHandler],
    ['DELETE', `/api/notes/${id}`, itemHandler], ['GET', '/api/notices', noticesHandler],
  ]) {
    const expected = url === '/api/notices' ? 'instructor_notices' : 'notes';
    const forged = expected === 'notes' ? 'instructor_notices' : 'notes';
    const response = responseCapture();
    await handle({ method, url: `${url}?resourceId=${forged}`,
      headers: { 'x-aleph-resource-id': forged }, query: { resourceId: forged },
      body: { resourceId: forged } }, response);
    assert.equal(response.code, 401);
    assert.deepEqual(response.body, { error: 'LOGIN_REQUIRED' });
    assert.equal(response.headers['x-aleph-resource-id'], expected);
  }
});

test('authenticated notices GET returns an empty independent resource without touching notes DB', async () => {
  await configured(async () => {
    mockUpstream(() => { throw new Error('Notice request must not access the notes DB'); });
    const response = responseCapture();
    await noticesHandler({ method: 'GET', url: '/api/notices',
      headers: { authorization: await authorization() } }, response);
    assert.equal(response.code, 200);
    assert.deepEqual(response.body, []);
    assert.equal(response.headers['x-aleph-resource-id'], 'instructor_notices');
    assert.equal(response.headers['cache-control'], 'no-store');

    const invalid = responseCapture();
    await noticesHandler({ method: 'GET', url: '/api/notices',
      headers: { authorization: 'Bearer invalid' } }, invalid);
    assert.equal(invalid.code, 401);
    assert.deepEqual(invalid.body, { error: 'LOGIN_REQUIRED' });
    assert.equal(invalid.headers['x-aleph-resource-id'], 'instructor_notices');
  });
});

test('notices refuse writes and unknown paths without accessing external services', async () => {
  await configured(async () => {
    globalThis.fetch = async () => { throw new Error('Must not fetch'); };
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      const response = responseCapture();
      await noticesHandler({ method, url: '/api/notices', headers: {} }, response);
      assert.equal(response.code, 401);
      assert.deepEqual(response.body, { error: 'LOGIN_REQUIRED' });
      assert.equal(response.headers['x-aleph-resource-id'], 'instructor_notices');
    }
    const response = responseCapture();
    await noticesHandler({ method: 'GET', url: '/api/notices/unknown', headers: {} }, response);
    assert.equal(response.code, 404);
  });
});

test('private list alias preserves own notes, hides foreign notes and rejects writes and anonymous requests', async () => {
  await configured(async () => {
    const { store, operations } = mockDatabase();
    store.get(rows[0].id).owner_id = subject;
    store.get(rows[1].id).owner_id = randomUUID();
    const before = structuredClone([...store]);
    const response = responseCapture();
    await ownListHandler({ method: 'GET', url: '/api/my/notes?owner_id=forged',
      headers: { authorization: await authorization() },
      body: { userId: store.get(rows[1].id).owner_id, role: 'instructor' } }, response);
    assert.equal(response.code, 200);
    assert.deepEqual(response.body.map(note => note.id), [rows[0].id]);
    assert.ok(operations.every(operation => operation.owner === subject));
    assert.equal(response.headers['x-aleph-resource-id'], 'notes');
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      const rejected = responseCapture();
      await ownListHandler({ method, url: '/api/my/notes', headers: {} }, rejected);
      assert.equal(rejected.code, 405);
      assert.equal(rejected.headers.allow, 'GET');
    }
    const anonymous = responseCapture();
    await ownListHandler({ method: 'GET', url: '/api/my/notes', headers: {} }, anonymous);
    assert.equal(anonymous.code, 401);
    assert.deepEqual(anonymous.body, { error: 'LOGIN_REQUIRED' });
    assert.deepEqual([...store], before);
  });
});

test('direct foreign note requests with a forged instructor role disclose no data and log only short codes', async () => {
  await configured(async () => {
    const { store } = mockDatabase();
    const id = rows[0].id;
    store.get(id).owner_id = subject;
    const before = structuredClone(store.get(id));
    const caller = randomUUID();
    const bearer = await authorization({ sub: caller });
    const logs = [];
    const originalWarn = console.warn;
    console.warn = value => logs.push(JSON.parse(value));
    try {
      for (const method of ['GET', 'PUT', 'DELETE']) {
        const response = responseCapture();
        await itemHandler({ method, url: `/api/notes/${id}`, headers: {
          authorization: bearer, 'x-role': 'instructor', 'x-user-id': subject,
          'x-aleph-resource-id': 'instructor_notices' },
        body: { title: 'Must not change', body: 'Must not change', role: 'instructor', userId: subject } }, response);
        assert.equal(response.code, 404);
        assert.deepEqual(response.body, { error: 'NOTE_NOT_FOUND' });
        assert.deepEqual(store.get(id), before);
      }
      assert.deepEqual(logs, Array(3).fill({
        event: 'api_denied', resourceId: 'notes', reason: 'NOTE_NOT_FOUND',
      }));
      assert.ok(!JSON.stringify(logs).includes(id));
      assert.ok(!JSON.stringify(logs).includes(caller));
    } finally { console.warn = originalWarn; }
  });
});

test('notice write permission is read from current stored app metadata, never client roles or stale claims', async () => {
  await configured(async () => {
    let permissions = [];
    let reads = 0;
    mockUpstream(() => { throw new Error('Must not access notes DB'); }, (url, options) => {
      assert.equal(url.pathname, `/auth/v1/admin/users/${subject}`);
      assert.equal(options.method, 'GET');
      assert.equal(options.body, undefined);
      assert.equal(options.redirect, 'error');
      assert.equal(options.cache, 'no-store');
      reads++;
      return new Response(JSON.stringify({ user: { id: subject,
        app_metadata: { aleph_permissions: permissions },
        user_metadata: { role: 'instructor', aleph_permissions: ['instructor_notices.write'] } } }));
    });
    const bearer = await authorization({ app_metadata: { aleph_permissions: ['instructor_notices.write'] } });
    async function send() {
      const response = responseCapture();
      await noticesHandler({ method: 'PUT', url: '/api/notices', headers: {
        authorization: bearer, 'x-role': 'instructor' },
      body: { role: 'instructor', userId: randomUUID(), aleph_permissions: ['instructor_notices.write'] } }, response);
      return response;
    }
    const missing = await send();
    assert.equal(missing.code, 403);
    assert.deepEqual(missing.body, { error: 'NOTICE_WRITE_NOT_ALLOWED' });
    permissions = ['instructor_notices.write'];
    const granted = await send();
    assert.equal(granted.code, 405); // Permission alone does not implement storage.
    assert.deepEqual(granted.body, { error: 'METHOD_NOT_ALLOWED' });
    assert.equal(granted.headers.allow, 'GET');
    permissions = []; // Revocation takes effect without changing the signed token.
    assert.equal((await send()).code, 403);
    assert.equal(reads, 3);
  });
});

test('notice authority lookup failures and mismatched stored users fail closed without leaking upstream data', async () => {
  await configured(async () => {
    const bearer = await authorization();
    const saved = { log: console.log, error: console.error, warn: console.warn };
    const logs = [];
    for (const method of Object.keys(saved)) console[method] = (...args) => logs.push(args);
    try {
      for (const [upstream, status, reason] of [
        [() => new Response(JSON.stringify({ msg: key }), { status: 503 }), 503, 'NOTICE_PERMISSION_UNAVAILABLE'],
        [() => { throw new Error(key); }, 503, 'NOTICE_PERMISSION_UNAVAILABLE'],
        [() => new Response(JSON.stringify({ user: { id: randomUUID(),
          app_metadata: { aleph_permissions: ['instructor_notices.write'] } } })), 403, 'NOTICE_WRITE_NOT_ALLOWED'],
        [() => new Response(JSON.stringify({ user: { id: subject,
          app_metadata: { aleph_permissions: 'instructor_notices.write' } } })), 403, 'NOTICE_WRITE_NOT_ALLOWED'],
      ]) {
        mockUpstream(() => { throw new Error('Must not access notes DB'); }, upstream);
        const response = responseCapture();
        await noticesHandler({ method: 'PUT', url: '/api/notices',
          headers: { authorization: bearer }, body: { role: 'instructor' } }, response);
        assert.equal(response.code, status);
        assert.deepEqual(response.body, { error: reason });
      }
      assert.equal(logs.length, 4);
      assert.ok(logs.every(args => {
        const entry = JSON.parse(args[0]);
        return args.length === 1 && Object.keys(entry).sort().join(',') === 'event,reason,resourceId'
          && entry.event === 'api_denied' && entry.resourceId === 'instructor_notices';
      }));
      assert.ok(!JSON.stringify(logs).includes(key));
      assert.ok(!JSON.stringify(logs).includes(subject));
    } finally { Object.assign(console, saved); }
  });
});

test('logout clears the editor and ignores a late save response', async () => {
  let finishSave;
  const session = { user: { id: subject }, access_token: (await authorization()).slice(7) };
  const page = await mountPage(async (_path, options) => {
    if (options.method === 'POST') return new Promise(resolve => { finishSave = resolve; });
    return new Response('[]');
  }, session);
  const get = id => page.elements.get('#' + id);
  get('note-title').value = 'Synthetic pending note';
  get('note-body').value = 'Synthetic pending body';
  const pending = get('note-form').listeners.submit({ preventDefault() {} });
  page.changeSession('SIGNED_OUT', null);
  finishSave(new Response(JSON.stringify({ id: randomUUID() }), { status: 201 }));
  await pending;
  assert.equal(get('note-editor').hidden, true);
  assert.equal(get('note-title').value, '');
  assert.equal(get('note-body').value, '');
  assert.match(get('notes').children[0].textContent, /로그인 후/u);
  assert.equal(get('note-message').textContent, '');
});
