import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import handler from '../api/notes.js';

const key = 'test-server-only-credential';
const rows = Array.from({ length: 4 }, (_, index) => ({ title: `DB title ${index + 1}`,
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
  process.env.SUPABASE_URL = 'https://learning-example.supabase.co';
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

test('public GET reads four DB notes with a server-only apikey and strips extra fields', async () => {
  await configured(async () => {
    globalThis.fetch = async (url, options) => {
      assert.equal(url.origin, process.env.SUPABASE_URL);
      assert.equal(url.pathname, '/rest/v1/notes');
      assert.equal(url.searchParams.get('select'), 'title,content');
      assert.equal(url.searchParams.get('limit'), '4');
      assert.equal(options.headers.apikey, key);
      assert.equal(options.headers.Authorization, undefined);
      assert.equal(options.redirect, 'error');
      assert.ok(options.signal instanceof AbortSignal);
      return new Response(JSON.stringify(rows.map(row => ({ ...row, internal_key: key, owner_id: 'hidden' }))));
    };
    const response = responseCapture();
    // Client input must not replace the configured DB URL or server credential.
    await handler({ method: 'GET', query: { url: 'https://untrusted.example', key: 'untrusted' } }, response);
    assert.equal(response.code, 200);
    assert.deepEqual(response.body, { notes: rows });
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.equal(response.headers['vercel-cdn-cache-control'], 'no-store');
    assert.ok(!JSON.stringify(response).includes(key));
  });
});

test('missing or unsafe configuration fails without fetching or leaking values', async () => {
  await configured(async () => {
    globalThis.fetch = async () => { throw new Error('Must not fetch'); };
    for (const [url, credential] of [
      ['https://learning-example.supabase.co', undefined],
      [undefined, key], ['http://learning-example.supabase.co', key],
      ['https://user:password@learning-example.supabase.co', key],
      ['https://learning-example.supabase.co/?apikey=anything', key],
    ]) {
      if (url === undefined) delete process.env.SUPABASE_URL;
      else process.env.SUPABASE_URL = url;
      if (credential === undefined) delete process.env.SUPABASE_SECRET_KEY;
      else process.env.SUPABASE_SECRET_KEY = credential;
      const response = responseCapture();
      await handler({ method: 'GET' }, response);
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
        globalThis.fetch = async () => result();
        const response = responseCapture();
        await handler({ method: 'GET' }, response);
        assert.equal(response.code, 502);
        assert.deepEqual(response.body, { error: 'NOTES_UNAVAILABLE' });
        assert.ok(!JSON.stringify(response).includes(key));
      }
      assert.deepEqual(logs, []);
    } finally { Object.assign(console, savedConsole); }
  });
});

test('writes are refused without querying the DB', async () => {
  await configured(async () => {
    globalThis.fetch = async () => { throw new Error('Must not fetch'); };
    const response = responseCapture();
    await handler({ method: 'POST' }, response);
    assert.equal(response.code, 405);
    assert.equal(response.headers.allow, 'GET');
  });
});

test('page fetches only the server route and renders four cards as text', async () => {
  await configured(async () => {
    const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
    assert.ok(!html.includes('SUPABASE_SECRET_KEY') && !html.includes('SUPABASE_URL'));
    const script = html.match(/<script type="module">([\s\S]*?)<\/script>/u)[1];
    const list = { children: [], replaceChildren(...children) { this.children = children; } };
    const document = {
      querySelector: () => list,
      createElement(tag) {
        return { tag, children: [], textContent: '', append(...children) { this.children.push(...children); },
          set innerHTML(_) { throw new Error('Use textContent'); } };
      },
    };
    const suppliedRows = rows.map(row => ({ ...row, title: `<img onerror=alert(1)>${row.title}` }));
    globalThis.fetch = async () => new Response(JSON.stringify(suppliedRows));
    const browserFetch = async (path, options) => {
      assert.equal(path, '/api/notes');
      assert.deepEqual(options, { cache: 'no-store' });
      const response = responseCapture();
      await handler({ method: 'GET' }, response);
      return new Response(JSON.stringify(response.body), { status: response.code });
    };
    const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
    await new AsyncFunction('document', 'fetch', script)(document, browserFetch);
    assert.equal(list.children.length, 4);
    assert.deepEqual(list.children.map(card => card.children.map(child => child.textContent)),
      suppliedRows.map(row => [row.title, row.content]));
  });
});
