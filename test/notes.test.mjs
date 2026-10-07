import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import handler from '../api/notes.js';
import itemHandler from '../api/notes/[id].js';

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

function mockUpstream(notesResponse) {
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
  process.env.SUPABASE_URL = new URL(config.identityProvider.issuer).origin;
  process.env.SUPABASE_SECRET_KEY = key;
  try { await work(); }
  finally {
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
      assert.equal(url.searchParams.get('select'), 'id,title,content');
      assert.equal(url.searchParams.get('owner_id'), `eq.${subject}`);
      assert.equal(url.searchParams.has('limit'), false);
      assert.equal(options.headers.apikey, key);
      assert.equal(options.headers.Authorization, undefined);
      assert.equal(options.redirect, 'error');
      assert.ok(options.signal instanceof AbortSignal);
      return new Response(JSON.stringify(rows.map(row => ({ ...row, internal_key: key, owner_id: 'hidden' }))));
    });
    const response = responseCapture();
    // Client input must not replace the configured DB URL or server credential.
    await handler({ method: 'GET', headers: { authorization: await authorization() },
      query: { url: 'https://untrusted.example', key: 'untrusted', userId: 'untrusted', role: 'service_role' } }, response);
    assert.equal(response.code, 200);
    assert.deepEqual(response.body, rows.map(({ id, title, content }) => ({ id, title, body: content })));
    assert.equal(response.headers['cache-control'], 'no-store');
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
      assert.deepEqual(logs, []);
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

async function mountPage(browserFetch, initialSession = null) {
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
  let changeSession;
  const browserGlobal = { supabase: { createClient() { return { auth: {
    onAuthStateChange(callback) { changeSession = callback; },
    async getSession() { return { data: { session: initialSession }, error: null }; },
  } }; } } };
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  await new AsyncFunction('document', 'fetch', 'globalThis', script)(document, browserFetch, browserGlobal);
  return { elements, changeSession };
}

test('page makes no anonymous read, sends only the SDK token, renders text, and clears notes on logout', async () => {
  let requests = 0;
  const token = (await authorization()).slice('Bearer '.length);
  const suppliedRows = rows.map(row => ({ ...row, title: `<img onerror=alert(1)>${row.title}` }));
  const page = await mountPage(async (path, options) => {
    requests++;
    assert.equal(path, '/api/notes');
    assert.equal(options.cache, 'no-store');
    assert.deepEqual(Object.keys(options.headers), ['Authorization']);
    assert.ok(options.headers.Authorization === `Bearer ${token}`);
    return new Response(JSON.stringify(suppliedRows.map(({ id, title, content }) => ({ id, title, body: content }))));
  });
  const list = page.elements.get('#notes');
  assert.equal(requests, 0);
  assert.match(list.children[0].textContent, /로그인 후/u);
  const session = { user: { id: subject }, access_token: token };
  page.changeSession('SIGNED_IN', session);
  await new Promise(setImmediate);
  assert.equal(list.children.length, 4);
  assert.deepEqual(list.children.map(card => card.children.slice(0, 2).map(child => child.textContent)),
    suppliedRows.map(row => [row.title, row.content]));
  page.changeSession('TOKEN_REFRESHED', session);
  assert.equal(requests, 1);
  page.changeSession('SIGNED_OUT', null);
  assert.equal(list.children.length, 1);
  assert.match(list.children[0].textContent, /로그인 후/u);
  assert.equal(page.elements.get('#login-form').hidden, false);
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
    const updated = await send('PUT', `/api/notes/${id}`, { id: suppliedId,
      title: 'Synthetic updated title', body: 'Synthetic updated body', owner_id: randomUUID() });
    assert.deepEqual(updated.body, { id, title: 'Synthetic updated title', body: 'Synthetic updated body' });
    assert.equal(store.get(id).owner_id, subject);
    assert.equal((await send('DELETE', `/api/notes/${id}`)).code, 200);
    assert.equal((await send('GET', `/api/notes/${id}`)).code, 404);
    assert.equal((await send('PUT', `/api/notes/${id}`, { title: 'Missing', body: '' })).code, 404);
    assert.equal((await send('DELETE', `/api/notes/${id}`)).code, 404);
    assert.ok(operations.filter(op => op.method === 'GET' && !op.id).every(op => op.owner === subject));
    for (const row of rows) assert.deepEqual(store.get(row.id), { ...row, owner_id: null });
    assert.deepEqual(config.allowedRoutes, ['GET /api/notes', 'POST /api/notes',
      'GET /api/notes/:id', 'PUT /api/notes/:id', 'DELETE /api/notes/:id']);
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
