import { createHash } from 'node:crypto';

const APP_PATH = '/api/apps/aleph-on/v1';
const CAPABILITIES = Object.freeze({models:'ai.models',explain:'ai.explain'});
const CONTEXT_KEYS = ['alephUserId','siteId','identityVersion','credentialId','grantId','grantVersion','policyVersion','accessPolicyId','modelPolicyVersion'];
const IDENTITY_KEYS = ['alephUserId','siteId','identityVersion'];
const RESPONSE_KEYS = ['appId','audience','subjectId','alephUserId','siteId','projectId','credentialId','grantId','grantVersion','identityVersion','policyVersion','accessPolicyId',
  'purpose','requiredCapability','capabilities','validUntil','revoked','credentialFingerprint','allowedModels','modelPolicyVersion'];
const verified = new WeakMap();
const own = code => Object.assign(new Error(code),{code});
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value,keys) => record(value) && Object.keys(value).length === keys.length && keys.every(key=>Object.hasOwn(value,key));
const opaque = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(value);
const subject = value => typeof value === 'string' && value.length > 0 && value.length <= 200 && value === value.trim() && !/[\u0000-\u001f\u007f]/.test(value);
const modelId = value => typeof value === 'string' && value.length <= 100 && /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/.test(value);
const positive = value => Number.isSafeInteger(value) && value > 0;

export function validateOnAppBaseUrl(baseUrl,{allowLoopbackHttp=false}={}) {
  let url;
  try { url = new URL(baseUrl); } catch { throw own('WB_CLCO_INVALID_URL'); }
  const loopback = ['127.0.0.1','localhost','[::1]'].includes(url.hostname);
  if (typeof baseUrl !== 'string' || url.username || url.password || url.search || url.hash || url.pathname !== APP_PATH
    || url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback && allowLoopbackHttp === true)) throw own('WB_CLCO_INVALID_URL');
  return url.href;
}

/** Only genuine proofs produced by this module's HTTP verifier can enable the live service branch. */
export function isVerifiedOnAppAuthorization(proof,{baseUrl,token,allowLoopbackHttp=false,signal,purpose}={}) {
  try {
    const metadata = verified.get(proof);
    return Boolean(metadata && metadata.baseUrl === validateOnAppBaseUrl(baseUrl,{allowLoopbackHttp})
      && metadata.fingerprint === createHash('sha256').update(token).digest('hex') && Date.parse(proof.validUntil) > Date.now()
      && !metadata.signal?.aborted && (signal === undefined || metadata.signal === signal)
      && (purpose === undefined || metadata.purpose === purpose));
  } catch { return false; }
}

export function createOnAppAuthorizationVerifier({baseUrl,token,allowLoopbackHttp=false,timeoutMs=10000,maxResponseBytes=16384,
  fetchImpl=globalThis.fetch,resolveExpectedContext}={}) {
  const base = validateOnAppBaseUrl(baseUrl,{allowLoopbackHttp});
  if (typeof token !== 'string' || !/^sk-on-[A-Za-z0-9_-]{43}$/.test(token)) throw own('WB_CLCO_INVALID_TOKEN');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 120000 || !Number.isSafeInteger(maxResponseBytes)
    || maxResponseBytes < 1 || maxResponseBytes > 65536 || typeof fetchImpl !== 'function'
    || resolveExpectedContext !== undefined && typeof resolveExpectedContext !== 'function') throw own('WB_CLCO_INVALID_LIMIT');
  const fingerprint = createHash('sha256').update(token).digest('hex');
  const authorizationUrl = base.slice(0,-'/v1'.length) + '/authorization';

  return async function verify({signal:externalSignal,purpose,requiredCapability,expectedScope,expectedContext}={}) {
    if (externalSignal?.aborted) throw own('WB_CLCO_CANCELLED');
    if (!Object.hasOwn(CAPABILITIES,purpose) || CAPABILITIES[purpose] !== requiredCapability
      || !exact(expectedScope,['subjectId','projectId','appId','audience']) || !subject(expectedScope.subjectId) || !opaque(expectedScope.projectId)
      || expectedScope.appId !== 'aleph-on' || expectedScope.audience !== 'on-client') throw own('ON_AI_PROVISIONING_PENDING');
    const scope = Object.freeze({...expectedScope});
    const controller = new AbortController();
    let timer, cancel;
    const stopped = new Promise((_,reject)=>{
      cancel = () => {controller.abort();reject(own('WB_CLCO_CANCELLED'));};
      timer = setTimeout(()=>{controller.abort();reject(own('WB_CLCO_TIMEOUT'));},timeoutMs);
      externalSignal?.addEventListener('abort',cancel,{once:true});
    });
    const check = () => {if(controller.signal.aborted)throw own('WB_CLCO_CANCELLED');};
    const work = async()=>{
      // This mapping comes from the current server identity/issuance source, never a browser payload.
      const context = structuredClone(expectedContext ?? (resolveExpectedContext ? await resolveExpectedContext(scope,{signal:controller.signal,purpose}) : null));
      check();
      if (!record(context) || !IDENTITY_KEYS.every(key=>Object.hasOwn(context,key)) || Object.keys(context).some(key=>!CONTEXT_KEYS.includes(key))
        || Object.keys(context).filter(key=>!['identityVersion','grantVersion'].includes(key)).some(key=>!opaque(context[key]))
        || !positive(context.identityVersion) || Object.hasOwn(context,'grantVersion') && !positive(context.grantVersion)
        || context.modelPolicyVersion !== undefined && context.policyVersion !== undefined && context.modelPolicyVersion !== context.policyVersion) throw own('ON_AI_PROVISIONING_PENDING');
      const response = await fetchImpl(authorizationUrl+'?purpose='+purpose,{method:'GET',headers:{authorization:`Bearer ${token}`,accept:'application/json'},
        signal:controller.signal,redirect:'manual',cache:'no-store',credentials:'omit'});
      check();
      if (response.status >= 300 && response.status < 400) throw own('WB_CLCO_REDIRECT_BLOCKED');
      if (response.status !== 200) throw own(response.status === 401 ? 'WB_CLCO_AUTH_REQUIRED' : response.status === 403 ? 'WB_CLCO_ACCESS_BLOCKED' : 'ON_AI_PROVISIONING_PENDING');
      if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(response.headers.get('content-type') ?? '')) throw own('WB_CLCO_INVALID_CONTENT_TYPE');
      const length = response.headers.get('content-length');
      if (length !== null && (!/^\d+$/.test(length) || Number(length) > maxResponseBytes)) throw own('WB_CLCO_RESPONSE_TOO_LARGE');
      if (!response.body) throw own('WB_CLCO_INVALID_RESPONSE');
      const reader = response.body.getReader(), chunks=[];
      let bytes=0;
      const abortRead = () => {void reader.cancel().catch(()=>{});};
      controller.signal.addEventListener('abort',abortRead,{once:true});
      try {
        while (true) {check();const next=await reader.read();check();if(next.done)break;bytes+=next.value.byteLength;
          if(bytes>maxResponseBytes)throw own('WB_CLCO_RESPONSE_TOO_LARGE');chunks.push(Buffer.from(next.value));}
      } finally {controller.signal.removeEventListener('abort',abortRead);await reader.cancel().catch(()=>{});reader.releaseLock();}
      let raw;
      try {raw=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));} catch {throw own('WB_CLCO_INVALID_RESPONSE');}
      check();
      if (!exact(raw,RESPONSE_KEYS) || raw.appId !== 'aleph-on' || raw.audience !== 'on-client' || raw.subjectId !== scope.subjectId || raw.projectId !== scope.projectId
        || Object.keys(context).some(key=>raw[key] !== context[key])
        || CONTEXT_KEYS.filter(key=>!['identityVersion','grantVersion'].includes(key)).some(key=>!opaque(raw[key]))
        || !positive(raw.identityVersion) || !positive(raw.grantVersion) || raw.purpose !== purpose || raw.requiredCapability !== requiredCapability
        || raw.revoked !== false || raw.credentialFingerprint !== fingerprint || !/^[a-f0-9]{64}$/.test(raw.credentialFingerprint)
        || !Array.isArray(raw.capabilities) || !raw.capabilities.length || raw.capabilities.length>2 || new Set(raw.capabilities).size!==raw.capabilities.length
        || raw.capabilities.some(cap=>!Object.values(CAPABILITIES).includes(cap)) || !raw.capabilities.includes(requiredCapability)
        || typeof raw.validUntil !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(raw.validUntil)
        || !Number.isFinite(Date.parse(raw.validUntil)) || new Date(raw.validUntil).toISOString() !== raw.validUntil || Date.parse(raw.validUntil)<=Date.now()
        || !Array.isArray(raw.allowedModels) || !raw.allowedModels.length || raw.allowedModels.length>64 || raw.allowedModels.some(value=>!modelId(value))
        || new Set(raw.allowedModels).size!==raw.allowedModels.length || raw.modelPolicyVersion !== raw.policyVersion) throw own('ON_AI_PROVISIONING_PENDING');
      const proof = Object.freeze({...raw,capabilities:Object.freeze([...raw.capabilities]),allowedModels:Object.freeze([...raw.allowedModels]),mode:'verified',
        appKeyScope:scope});
      verified.set(proof,{baseUrl:base,fingerprint,signal:externalSignal,purpose});
      return proof;
    };
    try {return await Promise.race([work(),stopped]);}
    catch(error){
      const known=new Set(['ON_AI_PROVISIONING_PENDING','WB_CLCO_CANCELLED','WB_CLCO_TIMEOUT','WB_CLCO_REDIRECT_BLOCKED','WB_CLCO_AUTH_REQUIRED','WB_CLCO_ACCESS_BLOCKED','WB_CLCO_INVALID_CONTENT_TYPE','WB_CLCO_RESPONSE_TOO_LARGE','WB_CLCO_INVALID_RESPONSE']);
      throw own(known.has(error?.code)?error.code:externalSignal?.aborted?'WB_CLCO_CANCELLED':'WB_CLCO_NETWORK_ERROR');
    } finally {clearTimeout(timer);externalSignal?.removeEventListener('abort',cancel);controller.abort();}
  };
}
