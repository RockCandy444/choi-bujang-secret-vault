// Internal derivative of Workbench transport; dedicated finite learner-support endpoint added.
import {types} from 'node:util';
const supportRecord=(value,keys)=>{
  if(value===null||typeof value!=='object'||types.isProxy(value)||Object.getPrototypeOf(value)!==Object.prototype)throw fail('WB_CLCO_INVALID_REQUEST');
  const descriptors=Object.getOwnPropertyDescriptors(value);
  if(Reflect.ownKeys(descriptors).length!==keys.length||keys.some(key=>!Object.hasOwn(descriptors,key)||!Object.hasOwn(descriptors[key],'value')))throw fail('WB_CLCO_INVALID_REQUEST');
  return Object.fromEntries(keys.map(key=>[key,descriptors[key].value]));
};
const supportAborted=Object.getOwnPropertyDescriptor(AbortSignal.prototype,'aborted').get;
function supportOptions(value){
  if(value===null||typeof value!=='object'||types.isProxy(value)||Object.getPrototypeOf(value)!==Object.prototype)throw fail('WB_CLCO_INVALID_REQUEST');
  const descriptors=Object.getOwnPropertyDescriptors(value);
  if(Reflect.ownKeys(descriptors).some(key=>key!=='signal'||!Object.hasOwn(descriptors[key],'value')))throw fail('WB_CLCO_INVALID_REQUEST');
  const signal=Object.hasOwn(descriptors,'signal')?descriptors.signal.value:undefined;
  if(signal!==undefined){if(signal===null||typeof signal!=='object'||types.isProxy(signal))throw fail('WB_CLCO_INVALID_REQUEST');
    try{Reflect.apply(supportAborted,signal,[]);}catch{throw fail('WB_CLCO_INVALID_REQUEST');}}
  return {signal};
}
const ownError = Symbol('workbench-http-error');
function fail(code, status = null, serverCode = null) {
  const error = new Error(code);
  error[ownError] = true;
  Object.assign(error, { code, status, serverCode });
  return error;
}
const safeCode = value => typeof value === 'string' && /^[A-Z][A-Z0-9_]{0,95}$/.test(value) ? value : 'UNKNOWN';

function serverFailure(status, payload) {
  const serverCode = safeCode(payload?.error?.code ?? payload?._clco?.blockedReason);
  let code = 'WB_CLCO_REQUEST_FAILED';
  if (status === 401) code = 'WB_CLCO_AUTH_REQUIRED';
  else if (['OUTSIDE_SESSION_WINDOW', 'SESSION_WINDOW_CLOSED', 'SESSION_FORCE_STOPPED'].includes(serverCode)) code = 'WB_CLCO_SESSION_CLOSED';
  else if (serverCode === 'COHORT_BUDGET_EXHAUSTED') code = 'WB_CLCO_COHORT_BUDGET_EXHAUSTED';
  else if (serverCode === 'RATE_LIMITED') code = 'WB_CLCO_RATE_LIMITED';
  else if (status === 403) code = 'WB_CLCO_ACCESS_BLOCKED';
  else if (status === 429) code = 'WB_CLCO_LIMIT_REACHED';
  else if (status >= 300 && status < 400) code = 'WB_CLCO_REDIRECT_BLOCKED';
  else if (status >= 500) code = 'WB_CLCO_SERVER_UNAVAILABLE';
  return fail(code, status, serverCode);
}

export function createClcoClient({ baseUrl, token, timeoutMs = 10000, maxResponseBytes = 1048576, allowLoopbackHttp = false } = {}) {
  let base;
  try { base = new URL(baseUrl); } catch { throw fail('WB_CLCO_INVALID_URL'); }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname);
  if ((base.protocol !== 'https:' && !(base.protocol === 'http:' && loopback && allowLoopbackHttp)) || base.username || base.password || base.search || base.hash) {
    throw fail('WB_CLCO_INVALID_URL');
  }
  base.pathname = base.pathname.replace(/\/+$/, '') || '/v1';
  if (!base.pathname.endsWith('/v1')) throw fail('WB_CLCO_INVALID_URL');
  if (typeof token !== 'string' || !/^[A-Za-z0-9._~-]+$/.test(token)) throw fail('WB_CLCO_INVALID_TOKEN');
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 120000 || !Number.isInteger(maxResponseBytes) || maxResponseBytes <= 0) {
    throw fail('WB_CLCO_INVALID_LIMIT');
  }

  async function request(endpoint, body, { signal, readStream } = {}) {
    const support=endpoint==='/learner-support';
    if (signal && (support?Reflect.apply(supportAborted,signal,[]):signal.aborted)) throw fail('WB_CLCO_CANCELLED');
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs);
    const cancel = () => controller.abort();
    if(signal){if(support)Reflect.apply(EventTarget.prototype.addEventListener,signal,['abort',cancel,{once:true}]);else signal.addEventListener('abort',cancel,{once:true});}
    try {
      const response = await fetch(base.href.replace(/\/$/, '') + endpoint, {
        method: body ? 'POST' : 'GET',
        headers: { authorization: `Bearer ${token}`, accept: body?.stream ? 'text/event-stream' : 'application/json', ...(body ? { 'content-type': 'application/json' } : {}) },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
        redirect: 'manual',
      });
      if(endpoint==='/learner-support'&&response.ok&&!/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(response.headers.get('content-type')??''))throw fail('WB_CLCO_INVALID_CONTENT_TYPE',response.status);
      async function* boundedBytes() {
        let size = 0;
        if (!response.body) throw fail('WB_CLCO_INVALID_RESPONSE', response.status);
        for await (const bytes of response.body) {
          size += bytes.byteLength;
          if (size > maxResponseBytes) throw fail('WB_CLCO_RESPONSE_TOO_LARGE', response.status);
          yield bytes;
        }
      }
      if (response.ok && body?.stream) {
        if (!/^text\/event-stream(?:;|$)/i.test(response.headers.get('content-type') ?? '')) throw fail('WB_CLCO_INVALID_CONTENT_TYPE', response.status);
        return await readStream(boundedBytes(), { maxBytes: maxResponseBytes });
      }
      const bytes = [];
      for await (const chunk of boundedBytes()) bytes.push(chunk);
      let payload;
      try { payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(bytes))); }
      catch {
        if (!response.ok) throw serverFailure(response.status, null);
        throw fail('WB_CLCO_INVALID_RESPONSE', response.status);
      }
      if (!response.ok || payload?.error || payload?._clco?.syntheticBlocked === true) throw serverFailure(response.status, payload);
      return payload;
    } catch (error) {
      if (error?.[ownError]) throw error;
      if (timedOut) throw fail('WB_CLCO_TIMEOUT');
      if (signal && (support?Reflect.apply(supportAborted,signal,[]):signal.aborted)) throw fail('WB_CLCO_CANCELLED');
      if (typeof error?.code === 'string' && /^WB_STREAM_[A-Z_]+$/.test(error.code)) {
        const safe = fail(error.code);
        safe.serverCode = safeCode(error.serverCode);
        throw safe;
      }
      throw fail('WB_CLCO_NETWORK_ERROR');
    } finally {
      clearTimeout(timer);
      if(signal){if(support)Reflect.apply(EventTarget.prototype.removeEventListener,signal,['abort',cancel]);else signal.removeEventListener('abort',cancel);}
      controller.abort();
    }
  }

  return Object.freeze({
    async listModels(options) {
      const result = await request('/models', null, options);
      if (result?.object !== 'list' || !Array.isArray(result.data) || result.data.some(row => typeof row?.id !== 'string' || !row.id)) throw fail('WB_CLCO_INVALID_RESPONSE', 200);
      return result.data.map(row => ({ id: row.id }));
    },
    async chat(body, options = {}) {
      if (!body || typeof body.model !== 'string' || !body.model || !Array.isArray(body.messages) || !body.messages.length || (body.stream !== undefined && typeof body.stream !== 'boolean')) throw fail('WB_CLCO_INVALID_REQUEST');
      if (body.stream && typeof options.readStream !== 'function') throw fail('WB_CLCO_STREAM_READER_REQUIRED');
      const result = await request('/chat/completions', body, options);
      if (!body.stream && (!Array.isArray(result?.choices) || !result.choices.length)) throw fail('WB_CLCO_INVALID_RESPONSE', 200);
      return result;
    },
    async learnerSupport(body, options = {}) {
      // This endpoint never falls back to chat/completions, including a 404 response.
      const finite=supportRecord(body,['model','problemKind','observations']),observed=supportRecord(finite.observations,['engine','ai']);
      const engine=supportRecord(observed.engine,['mode','code']),ai=supportRecord(observed.ai,['configured','authorized']);
      const modes={disconnected:'ENGINE_NOT_CONNECTED',demo:'DEMO_ONLY',connected:'ADAPTER_CONFIGURED'};
      if(typeof finite.model!=='string'||! /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$/.test(finite.model)
        ||!['app-start','engine-connection','ai-access','response-delay','diagnostic-copy'].includes(finite.problemKind)
        ||typeof engine.mode!=='string'||!Object.hasOwn(modes,engine.mode)||engine.code!==modes[engine.mode]
        ||typeof ai.configured!=='boolean'||ai.authorized!==false)throw fail('WB_CLCO_INVALID_REQUEST');
      const result=await request('/learner-support',{model:finite.model,problemKind:finite.problemKind,observations:{engine,ai}},supportOptions(options));
      if(result===null||typeof result!=='object'
        ||Object.keys(result).length!==2||!Object.hasOwn(result,'ok')||!Object.hasOwn(result,'data')||result.ok!==true)throw fail('WB_CLCO_INVALID_RESPONSE',200);
      return result;
    },
  });
}
