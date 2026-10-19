// Read-only OSV lookup. Public package approval is supplied by the caller, never inferred online.
export const OSV_QUERY_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactFields = (value, names) => plain(value) && Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
const npmName = value => typeof value === 'string' && value.length <= 214 && /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(value);
const version = value => {
  if (typeof value !== 'string' || value.length > 100 || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.test(value)) return false;
  const prerelease = value.split('+')[0].split('-').slice(1).join('-');
  return !prerelease || prerelease.split('.').every(part => !/^\d+$/.test(part) || part === '0' || !part.startsWith('0'));
};
function installedName(path) {
  if (typeof path !== 'string' || !path.includes('node_modules/') || /\\/.test(path) || path.split('/').some(part => ['.', '..', ''].includes(part))) return null;
  const candidate = path.split('node_modules/').at(-1);
  return npmName(candidate) ? candidate : null;
}
function registryTarballMatches(resolved, name, installedVersion) {
  if (typeof resolved !== 'string') return false;
  let url;
  try { url = new URL(resolved); } catch { return false; }
  if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.port || url.username || url.password || url.search || url.hash) return false;
  let path;
  try { path = decodeURIComponent(url.pathname); } catch { return false; }
  return path === `/${name}/-/${name.split('/').at(-1)}-${installedVersion}.tgz`;
}

export function buildPackageQueries(lock, { approvedPublicPackages = [] } = {}) {
  const excluded = { unapproved: 0, unsupported: 0, invalid: 0 };
  const queries = [];
  if (!plain(lock) || ![2, 3].includes(lock.lockfileVersion) || !plain(lock.packages)) return { queries, excluded: { ...excluded, unsupported: 1 }, lockfileVersion: null };
  const approved = new Set(Array.isArray(approvedPublicPackages) ? approvedPublicPackages.filter(npmName) : []);
  const seen = new Set();
  for (const [path, row] of Object.entries(lock.packages)) {
    if (path === '') continue; // The root application is not an installed dependency.
    const installed = installedName(path);
    if (!installed || !plain(row) || row.link === true || row.private === true) { excluded.unsupported++; continue; }
    // For npm aliases, package-lock records the actual package in row.name.
    const name = row.name === undefined ? installed : row.name;
    if (!npmName(name)) { excluded.invalid++; continue; }
    if (!approved.has(name)) { excluded.unapproved++; continue; }
    if (!version(row.version) || !registryTarballMatches(row.resolved, name, row.version)) { excluded.invalid++; continue; }
    const key = `${name}\n${row.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    queries.push({ package: { name, ecosystem: 'npm' }, version: row.version });
  }
  return { queries, excluded, lockfileVersion: lock.lockfileVersion };
}

const validQuery = query => exactFields(query, ['package', 'version']) && exactFields(query.package, ['name', 'ecosystem']) && npmName(query.package.name) && query.package.ecosystem === 'npm' && version(query.version);
const safeCursor = value => typeof value === 'string' && value.length > 0 && value.length <= 2048 && !/[\u0000-\u0020\u007f]/.test(value);
const validFinding = finding => plain(finding) && typeof finding.id === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/.test(finding.id)
  && typeof finding.modified === 'string' && finding.modified.length <= 40
  && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(finding.modified) && Number.isFinite(Date.parse(finding.modified));
const limitsValid = (timeoutMs, maxPages, maxResponseBytes) => Number.isInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 120000
  && Number.isInteger(maxPages) && maxPages > 0 && maxPages <= 100 && Number.isInteger(maxResponseBytes) && maxResponseBytes > 0 && maxResponseBytes <= 10485760;

function endpointFor(endpoint, allowLoopbackHttp) {
  if (endpoint === OSV_QUERY_BATCH_URL) return endpoint;
  let url;
  try { url = new URL(endpoint); } catch { return null; }
  if (!allowLoopbackHttp || !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) || !['http:', 'https:'].includes(url.protocol)
    || url.username || url.password || url.search || url.hash || url.pathname !== '/v1/querybatch') return null;
  return url.href;
}
async function readBoundedJson(response, maxBytes, signal) {
  const chunks = [];
  let bytes = 0;
  if (!response.body) throw new Error('OSV_INVALID_RESPONSE');
  for await (const chunk of response.body) {
    if (signal.aborted) throw new Error('OSV_CANCELLED');
    bytes += chunk.byteLength;
    if (bytes > maxBytes) throw new Error('OSV_RESPONSE_TOO_LARGE');
    chunks.push(chunk);
  }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
}

export function createOsvClient({ endpoint = OSV_QUERY_BATCH_URL, allowLoopbackHttp = false, fetchImpl = globalThis.fetch } = {}) {
  const url = endpointFor(endpoint, allowLoopbackHttp);
  return Object.freeze({
    async lookupPackages(queries, { signal: externalSignal, timeoutMs = 10000, maxPages = 10, maxResponseBytes = 1048576 } = {}) {
      if (!Array.isArray(queries)) return [];
      const checkedAt = new Date().toISOString();
      // Never echo extra fields, local paths, URLs, cursors or arbitrary error messages.
      const states = queries.map(query => ({ query: validQuery(query) ? structuredClone(query) : null,
        result: { name: npmName(query?.package?.name) ? query.package.name : null, version: version(query?.version) ? query.version : null,
          status: 'unverifiable', vulnerabilities: [], source: OSV_QUERY_BATCH_URL, checkedAt }, cursor: null, seenCursors: new Set(), finished: false }));
      const results = () => states.map(state => ({ ...state.result, vulnerabilities: state.result.vulnerabilities.map(row => ({ ...row })) }));
      if (!url || typeof fetchImpl !== 'function' || externalSignal?.aborted || !limitsValid(timeoutMs, maxPages, maxResponseBytes)) return results();
      const controller = new AbortController();
      let timer;
      let cancel;
      const stopped = new Promise((_, reject) => {
        cancel = () => { controller.abort(); reject(new Error('OSV_CANCELLED')); };
        timer = setTimeout(() => { controller.abort(); reject(new Error('OSV_TIMEOUT')); }, timeoutMs);
        externalSignal?.addEventListener('abort', cancel, { once: true });
      });
      const work = async () => {
        for (let page = 0; page < maxPages; page++) {
          const pending = states.filter(state => state.query && !state.finished);
          if (!pending.length || controller.signal.aborted) break;
          const response = await fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' },
            body: JSON.stringify({ queries: pending.map(state => ({ ...state.query, ...(state.cursor ? { page_token: state.cursor } : {}) })) }), redirect: 'manual', signal: controller.signal });
          if (controller.signal.aborted) break; // An uncooperative late fetch cannot process or dispatch more pages.
          if (!response?.ok || !Number.isInteger(response.status) || response.status >= 300 || response.status < 200) break;
          const payload = await readBoundedJson(response, maxResponseBytes, controller.signal);
          if (controller.signal.aborted) break;
          if (!plain(payload) || !Array.isArray(payload.results) || payload.results.length !== pending.length) break;
          for (let i = 0; i < pending.length; i++) {
            const state = pending[i];
            const row = payload.results[i];
            if (!plain(row) || Object.keys(row).some(key => !['vulns', 'next_page_token'].includes(key))
              || (row.vulns !== undefined && (!Array.isArray(row.vulns) || row.vulns.some(finding => !validFinding(finding))))
              || (row.next_page_token !== undefined && row.next_page_token !== '' && !safeCursor(row.next_page_token))) { state.finished = true; continue; }
            for (const finding of row.vulns ?? []) {
              const existing = state.result.vulnerabilities.find(value => value.id === finding.id);
              if (!existing) state.result.vulnerabilities.push({ id: finding.id, modified: finding.modified });
              else if (Date.parse(finding.modified) > Date.parse(existing.modified)) existing.modified = finding.modified;
            }
            const cursor = row.next_page_token;
            if (cursor) {
              if (state.seenCursors.has(cursor)) { state.finished = true; continue; }
              state.seenCursors.add(cursor);
              state.cursor = cursor;
            } else {
              state.finished = true;
              state.result.status = state.result.vulnerabilities.length ? 'known_vulnerabilities' : 'none_found';
            }
          }
        }
      };
      try { await Promise.race([work(), stopped]); }
      catch { /* Failure is an unverifiable comparison, never a clean bill of health. */ }
      finally { clearTimeout(timer); externalSignal?.removeEventListener('abort', cancel); controller.abort(); }
      return results();
    },
  });
}

export async function lookupPackages(queries, { endpoint = OSV_QUERY_BATCH_URL, allowLoopbackHttp = false, fetchImpl = globalThis.fetch, ...options } = {}) {
  return createOsvClient({ endpoint, allowLoopbackHttp, fetchImpl }).lookupPackages(queries, options);
}
