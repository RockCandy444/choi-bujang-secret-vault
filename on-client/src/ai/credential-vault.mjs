// Native host only. Never export this module, its input, or its output to a browser.
import {spawn} from 'node:child_process';
import {createHash, randomUUID} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const CONTEXT = ['subjectId','alephUserId','siteId','identityVersion','projectId'];
const CREDENTIAL = ['schema','appId','audience',...CONTEXT,'grantId','grantVersion','credentialId','policyVersion','accessPolicyId','baseUrl','token','expiresAt'];
const HELPER = fileURLToPath(new URL('../../tools/app-credentials.ps1', import.meta.url));
const POWERSHELL = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const DEFAULT_BASE = 'https://ai-classroom-gateway-production.up.railway.app/api/apps/aleph-on/v1';
const MAX_MESSAGE = 32768;
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
const exact = (v, keys) => plain(v) && Reflect.ownKeys(v).length === keys.length && keys.every(k => Object.hasOwn(v,k));
const id = v => typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$/.test(v);
const positive = v => Number.isSafeInteger(v) && v > 0;
const sha = v => createHash('sha256').update(v).digest('hex');
// Same canonicalization as connection.mjs; all keys are ASCII.
const canonical = v => JSON.stringify(Object.fromEntries(Object.entries(v).sort(([a],[b]) => a.localeCompare(b))));
const fingerprint = context => sha(canonical(context));
const fail = code => { throw Object.assign(new Error(code), {code}); };
const validContext = v => exact(v,CONTEXT) && CONTEXT.filter(k => k !== 'identityVersion').every(k => id(v[k])) && positive(v.identityVersion);
function validateCredential(v, context, baseUrl) {
  if (!exact(v,CREDENTIAL) || v.schema !== 'alekov.app-connect.credential.v1' || v.appId !== 'aleph-on' || v.audience !== 'on-client'
      || CONTEXT.some(k => v[k] !== context[k]) || ['grantId','credentialId','policyVersion','accessPolicyId'].some(k => !id(v[k]))
      || !positive(v.grantVersion) || v.baseUrl !== baseUrl || !/^sk-on-[A-Za-z0-9_-]{43}$/.test(v.token ?? '')
      || typeof v.expiresAt !== 'string' || !Number.isFinite(Date.parse(v.expiresAt)) || new Date(v.expiresAt).toISOString() !== v.expiresAt)
    fail('ALEKOV_VAULT_CREDENTIAL_INVALID');
  if (Date.parse(v.expiresAt) <= Date.now()) fail('ALEKOV_VAULT_EXPIRED');
}

/** Existing, empty owned directory on first use; a marked Alekov directory thereafter.
 * No default storage path, credential discovery, Workbench dependency, or browser API.
 * Host callbacks are checked at entry, just before commit, and after completion.
 * This is NOT a transaction with the host's identity state (see accompanying document).
 */
export function createAppCredentialVault({vaultRoot, resolveCurrentContext, baseUrl = DEFAULT_BASE, timeoutMs = 15000} = {}) {
  let url;
  try { url = new URL(baseUrl); } catch { fail('ALEKOV_VAULT_CONFIGURATION_INVALID'); }
  if (process.platform !== 'win32') fail('ALEKOV_VAULT_WINDOWS_REQUIRED');
  if (typeof vaultRoot !== 'string' || !path.win32.isAbsolute(vaultRoot) || !/^[A-Za-z]:\\/.test(vaultRoot)
      || vaultRoot.includes('\0') || vaultRoot.includes(':',2) || vaultRoot.startsWith('\\\\')
      || path.win32.parse(vaultRoot).root === path.win32.resolve(vaultRoot)
      || typeof resolveCurrentContext !== 'function' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120000
      || url.protocol !== 'https:' || url.username || url.password || url.search || url.hash
      || url.pathname !== '/api/apps/aleph-on/v1' || baseUrl !== url.origin + url.pathname)
    fail('ALEKOV_VAULT_CONFIGURATION_INVALID');
  const root = path.win32.resolve(vaultRoot);

  async function current(expected, alive) {
    alive();
    let value;
    try { value = structuredClone(await resolveCurrentContext()); } catch { fail('ALEKOV_VAULT_CONTEXT_UNVERIFIED'); }
    alive();
    if (!validContext(value)) fail('ALEKOV_VAULT_CONTEXT_UNVERIFIED');
    if (canonical(value) !== canonical(expected)) fail('ALEKOV_VAULT_CONTEXT_CHANGED');
  }

  async function execute(action, input, {signal} = {}) {
    if (!plain(input) || !validContext(input.expectedContext)) fail('ALEKOV_VAULT_CONTEXT_UNVERIFIED');
    const expected = structuredClone(input.expectedContext);
    if (action === 'save') {
      if (!exact(input,['connectionId','expectedContext','credential']) || !id(input.connectionId)) fail('ALEKOV_VAULT_INPUT_INVALID');
      validateCredential(input.credential,expected,baseUrl);
    } else if (action === 'load') {
      if (!exact(input,['expectedContext'])) fail('ALEKOV_VAULT_INPUT_INVALID');
    } else if (!exact(input,['expectedContext','credentialFingerprint']) || !/^[a-f0-9]{64}$/.test(input.credentialFingerprint ?? '')) fail('ALEKOV_VAULT_INPUT_INVALID');
    const snapshot = structuredClone(input);
    const deadline = Date.now() + timeoutMs;
    let child, timer, onAbort, settled = false;
    const alive = () => {
      if (signal?.aborted) fail('ALEKOV_VAULT_CANCELLED');
      if (Date.now() >= deadline) fail('ALEKOV_VAULT_TIMEOUT');
    };
    return new Promise((resolve,reject) => {
      const finish = (error,result) => {
        if (settled) return;
        settled = true; clearTimeout(timer); signal?.removeEventListener('abort',onAbort);
        child?.stdin.destroy(); if (child && child.exitCode === null) child.kill();
        if (error) reject(error); else resolve(result);
      };
      const abort = code => finish(Object.assign(new Error(code),{code}));
      onAbort = () => abort('ALEKOV_VAULT_CANCELLED');
      signal?.addEventListener('abort',onAbort,{once:true});
      timer = setTimeout(() => abort('ALEKOV_VAULT_TIMEOUT'),timeoutMs);
      void (async () => {
        alive(); await current(expected,alive); if (settled) return;
        const nonce = randomUUID();
        const request = {schema:'alekov.app-vault.request.v1',action,vaultRoot:root,baseUrl,deadline,nonce,
          expectedContext:expected,contextFingerprint:fingerprint(expected),
          connectionId:snapshot.connectionId ?? null,credential:snapshot.credential ?? null,credentialFingerprint:snapshot.credentialFingerprint ?? null};
        const message = JSON.stringify(request)+'\n';
        if (Buffer.byteLength(message) > MAX_MESSAGE) fail('ALEKOV_VAULT_INPUT_INVALID');
        child = spawn(POWERSHELL,['-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',HELPER],{
          windowsHide:true,shell:false,stdio:['pipe','pipe','pipe'],cwd:root,
          env:{SystemRoot:'C:\\Windows',WINDIR:'C:\\Windows'}
        });
        let buffer = '', total = 0, stage = 'starting', result;
        child.stdout.setEncoding('utf8');
        child.stderr.on('data',() => {}); // Never forward process diagnostics, including attacker supplied text.
        child.on('error',() => abort('ALEKOV_VAULT_EXECUTION_FAILED'));
        child.stdin.on('error',() => abort('ALEKOV_VAULT_OUTCOME_UNKNOWN'));
        child.on('close',code => {
          if (settled) return;
          if (code !== 0 || stage !== 'finished' || buffer.trim()) return abort('ALEKOV_VAULT_OUTCOME_UNKNOWN');
          void (async () => { await current(expected,alive); finish(null,result); })().catch(error => finish(error));
        });
        child.stdout.on('data',chunk => {
          total += Buffer.byteLength(chunk);
          if (total > MAX_MESSAGE) return abort('ALEKOV_VAULT_PROTOCOL_INVALID');
          buffer += chunk;
          let index;
          while ((index = buffer.indexOf('\n')) >= 0) {
            const line = buffer.slice(0,index).trim(); buffer = buffer.slice(index+1);
            let reply; try { reply = JSON.parse(line); } catch { abort('ALEKOV_VAULT_PROTOCOL_INVALID'); return; }
            if (exact(reply,['ok','code']) && reply.ok === false && /^ALEKOV_VAULT_[A-Z_]+$/.test(reply.code)) { abort(reply.code); return; }
            if (stage === 'starting' && exact(reply,['stage','nonce']) && reply.stage === 'ready' && reply.nonce === nonce) {
              stage = 'checking';
              void (async () => {
                await current(expected,alive); alive(); if (settled) return;
                if (action === 'save') validateCredential(snapshot.credential,expected,baseUrl);
                stage = 'committing'; child.stdin.end(JSON.stringify({commit:nonce})+'\n');
              })().catch(error => finish(error));
            } else if (stage === 'committing' && exact(reply,['ok','result']) && reply.ok === true) {
              try {
                alive();
                if (action === 'save') {
                  if (!exact(reply.result,['connectionId','credentialFingerprint','contextFingerprint','persisted']) || reply.result.connectionId !== snapshot.connectionId
                      || reply.result.credentialFingerprint !== sha(snapshot.credential.token) || reply.result.contextFingerprint !== fingerprint(expected) || reply.result.persisted !== true)
                    fail('ALEKOV_VAULT_PROTOCOL_INVALID');
                } else if (action === 'load') {
                  if (reply.result !== null) validateCredential(reply.result,expected,baseUrl);
                } else if (!exact(reply.result,['removed','contextFingerprint','credentialFingerprint']) || typeof reply.result.removed !== 'boolean'
                           || reply.result.contextFingerprint !== fingerprint(expected) || reply.result.credentialFingerprint !== snapshot.credentialFingerprint)
                  fail('ALEKOV_VAULT_PROTOCOL_INVALID');
                result = reply.result; stage = 'finished';
              } catch (error) { finish(error); }
            } else { abort('ALEKOV_VAULT_PROTOCOL_INVALID'); return; }
          }
        });
        child.stdin.write(message);
      })().catch(error => finish(error));
    });
  }
  return Object.freeze({
    persistCredential:(input,options) => execute('save',input,options),
    load:(input,options) => execute('load',input,options),
    remove:(input,options) => execute('remove',input,options)
  });
}
