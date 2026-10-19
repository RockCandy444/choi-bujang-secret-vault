// Trusted host only. Credentials live only inside one operation, never process.env.
import {createOnAiService,captureOnAiIncident} from './service.mjs';
import {validateOnAppBaseUrl} from './app-authorization.mjs';
import {types} from 'node:util';
import {buildLocalLearnerSupportGuide} from '../learner-support/service.mjs';

const IDENTITY = ['alephUserId','siteId','identityVersion'];
const PINS = ['credentialId','grantId','grantVersion','policyVersion','accessPolicyId','modelPolicyVersion'];
const CONTEXT = ['subjectId',...IDENTITY,'projectId'];
const CREDENTIAL = ['schema','appId','audience',...CONTEXT,'grantId','grantVersion','credentialId','policyVersion','accessPolicyId','baseUrl','token','expiresAt'];
const plain = v => v !== null && typeof v === 'object' && !types.isProxy(v) && Object.getPrototypeOf(v) === Object.prototype;
const data = v => plain(v) && Reflect.ownKeys(v).every(k => typeof k === 'string' && Object.hasOwn(Object.getOwnPropertyDescriptor(v,k),'value'));
const exact = (v,keys) => data(v) && Reflect.ownKeys(v).length === keys.length && keys.every(k=>Object.hasOwn(v,k));
const id = v => typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(v);
const subject = v => typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$/.test(v);
const positive = v => Number.isSafeInteger(v) && v > 0;
const own = code => Object.assign(new Error(code),{code});
const abortRead=Object.getOwnPropertyDescriptor(AbortSignal.prototype,'aborted').get;
const messages = Object.freeze({
  ON_AI_PROVISIONING_PENDING:'학생 앱 전용 이용 권한과 열쇠 발급을 준비 중입니다. 담당자에게 확인하세요.',
  WB_CLCO_CANCELLED:'AI 요청을 취소했습니다.',
  WB_CLCO_TIMEOUT:'AI 응답 시간이 초과됐습니다. 연결 상태를 확인하세요.',
});

export function createVaultOnAiService({enabled=false,vault,model='aleph/auto',timeoutMs=10000,transportFactory,appAuthorization}={}) {
  // No caller-supplied verifier or proof. The service constructs the genuine HTTP verifier.
  const configKeys=['fetchImpl','maxResponseBytes','allowLoopbackHttp'];
  const configured = enabled === true && typeof vault?.load === 'function'
    && typeof model === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$/.test(model)
    && positive(timeoutMs) && timeoutMs <= 120000
    && (transportFactory === undefined || typeof transportFactory === 'function')
    && data(appAuthorization) && Object.keys(appAuthorization).every(k=>configKeys.includes(k))
    && (appAuthorization.fetchImpl === undefined || typeof appAuthorization.fetchImpl === 'function')
    && (appAuthorization.maxResponseBytes === undefined || positive(appAuthorization.maxResponseBytes) && appAuthorization.maxResponseBytes <= 65536)
    && (appAuthorization.allowLoopbackHttp === undefined || typeof appAuthorization.allowLoopbackHttp === 'boolean');
  const authConfig = configured ? Object.freeze({...appAuthorization}) : null;
  const help = code => ({component:'on-ai',code,appCredentialsConfigured:false,provisioning:'pending',automaticRetries:0,workbenchRequiredAtRuntime:false});
  const failure = error => {
    const mapped=error?.code === 'ALEKOV_VAULT_TIMEOUT' ? 'WB_CLCO_TIMEOUT'
      : error?.code === 'ALEKOV_VAULT_CANCELLED' ? 'WB_CLCO_CANCELLED' : error?.code;
    const code=Object.hasOwn(messages,mapped) ? mapped : 'ON_AI_PROVISIONING_PENDING';
    return {ok:false,error:{code,message:messages[code]},help:help(code)};
  };
  function mapping(options) {
    const s=options.expectedScope,c=options.expectedContext;
    if (!exact(s,['subjectId','projectId','appId','audience']) || !subject(s.subjectId) || !id(s.projectId)
      || s.appId !== 'aleph-on' || s.audience !== 'on-client' || !data(c)
      || !IDENTITY.every(k=>Object.hasOwn(c,k)) || Object.keys(c).some(k=>![...IDENTITY,...PINS].includes(k))
      || Object.keys(c).some(k=>['identityVersion','grantVersion'].includes(k) ? !positive(c[k]) : !id(c[k]))) throw own('ON_AI_PROVISIONING_PENDING');
    return {scope:Object.freeze({...s}),context:Object.freeze({...c}),vaultContext:Object.freeze({subjectId:s.subjectId,projectId:s.projectId,...Object.fromEntries(IDENTITY.map(k=>[k,c[k]]))})};
  }
  function credential(raw,pins) {
    if (!exact(raw,CREDENTIAL)) throw own('ON_AI_PROVISIONING_PENDING');
    const v=Object.freeze({...raw});
    if (v.schema !== 'alekov.app-connect.credential.v1' || v.appId !== 'aleph-on' || v.audience !== 'on-client'
      || CONTEXT.some(k=>v[k] !== pins.vaultContext[k]) || !positive(v.grantVersion)
      || ['grantId','credentialId','policyVersion','accessPolicyId'].some(k=>!id(v[k]))
      || typeof v.token !== 'string' || !/^sk-on-[A-Za-z0-9_-]{43}$/.test(v.token)
      || typeof v.expiresAt !== 'string' || !Number.isFinite(Date.parse(v.expiresAt)) || new Date(v.expiresAt).toISOString() !== v.expiresAt
      || Date.parse(v.expiresAt) <= Date.now()) throw own('ON_AI_PROVISIONING_PENDING');
    try {if(validateOnAppBaseUrl(v.baseUrl,{allowLoopbackHttp:authConfig.allowLoopbackHttp === true}) !== v.baseUrl) throw own('ON_AI_PROVISIONING_PENDING');}
    catch {throw own('ON_AI_PROVISIONING_PENDING');}
    const context={...pins.context,...Object.fromEntries(PINS.map(k=>[k,k==='modelPolicyVersion'?v.policyVersion:v[k]]))};
    if (PINS.some(k=>Object.hasOwn(pins.context,k) && pins.context[k] !== context[k])) throw own('ON_AI_PROVISIONING_PENDING');
    return {value:v,context:Object.freeze(context)};
  }
  async function operation(method,input,options={},observation) {
    if(method==='explain'&&(!options||typeof options!=='object'||types.isProxy(options)))return failure(own('ON_AI_PROVISIONING_PENDING'));
    const incidentCallbacks=method==='explain'&&['beforeDispatch','beforePublish'].some(key=>Object.hasOwn(options,key));
    const guarded=method==='learner-support'||method==='models'||incidentCallbacks;
    if(guarded){
      try {
        if(!data(options)||Object.keys(options).some(key=>!['signal','expectedScope','expectedContext','beforeDispatch','beforePublish'].includes(key)))throw own('ON_AI_PROVISIONING_PENDING');
        const descriptors=Object.getOwnPropertyDescriptors(options);
        const pins=mapping(options);
        const signal=Object.hasOwn(descriptors,'signal')?descriptors.signal.value:undefined;
        const beforeDispatch=Object.hasOwn(descriptors,'beforeDispatch')?descriptors.beforeDispatch.value:undefined;
        const beforePublish=Object.hasOwn(descriptors,'beforePublish')?descriptors.beforePublish.value:undefined;
        if([beforeDispatch,beforePublish].some(callback=>callback!==undefined&&(typeof callback!=='function'||types.isProxy(callback))))throw own('ON_AI_PROVISIONING_PENDING');
        if(method==='models'||incidentCallbacks){
          if((beforeDispatch===undefined)!==(beforePublish===undefined)||incidentCallbacks&&(typeof beforeDispatch!=='function'||typeof beforePublish!=='function'))throw own('ON_AI_PROVISIONING_PENDING');
          if(incidentCallbacks)input=captureOnAiIncident(input);
          if(signal!==undefined){
            if(signal===null||typeof signal!=='object'||types.isProxy(signal))throw own('ON_AI_PROVISIONING_PENDING');
            let aborted;try{aborted=Reflect.apply(abortRead,signal,[]);}catch{throw own('ON_AI_PROVISIONING_PENDING');}
            if(aborted)throw own('WB_CLCO_CANCELLED');
          }
        }else{
          const guide=buildLocalLearnerSupportGuide(input,observation,{signal});
          // Capture the finite input, observations and mapping before vault.load can yield.
          input=Object.freeze({problemKind:guide.problemKind});observation=guide.observations;
        }
        options={signal,beforeDispatch,beforePublish,expectedScope:pins.scope,expectedContext:pins.context};
      }catch(error){return failure(error?.code==='REQUEST_CANCELLED'?own('WB_CLCO_CANCELLED'):error);}
    }
    if (options.signal && (guarded?Reflect.apply(abortRead,options.signal,[]):options.signal.aborted)) return failure(own('WB_CLCO_CANCELLED'));
    if (!configured) return failure(own('ON_AI_PROVISIONING_PENDING'));
    const controller=new AbortController();
    let timer,cancel;
    const deadline=Date.now()+timeoutMs;
    const monotonicDeadline=performance.now()+timeoutMs;
    const stopped=new Promise((_,reject)=>{
      cancel=()=>{controller.abort();reject(own('WB_CLCO_CANCELLED'));};
      timer=setTimeout(()=>{controller.abort();reject(own('WB_CLCO_TIMEOUT'));},timeoutMs);
      if(options.signal){if(guarded)Reflect.apply(EventTarget.prototype.addEventListener,options.signal,['abort',cancel,{once:true}]);else options.signal.addEventListener('abort',cancel,{once:true});}
    });
    const alive=()=>{
      if(controller.signal.aborted)throw own('WB_CLCO_CANCELLED');
      if(Date.now()>=deadline||guarded&&performance.now()>=monotonicDeadline)throw own('WB_CLCO_TIMEOUT');
    };
    const work=async()=>{
      // Snapshot the trusted mapping and incident before any callback can yield.
      const pins=mapping(options),incident=input === undefined ? undefined : structuredClone(input);
      alive();
      const loaded=await vault.load({expectedContext:pins.vaultContext},{signal:controller.signal});
      alive();
      const {value:v,context}=credential(loaded,pins);
      alive();
      const service=createOnAiService({env:{ON_AI_BASE_URL:v.baseUrl,ON_AI_APP_KEY:v.token,ON_AI_MODEL:model},model,
        timeoutMs:Math.max(1,deadline-Date.now()),transportFactory,allowLoopbackHttp:authConfig.allowLoopbackHttp === true,
        appAuthorization:{fetchImpl:authConfig.fetchImpl ?? globalThis.fetch,maxResponseBytes:authConfig.maxResponseBytes ?? 16384}});
      const serviceOptions={signal:controller.signal,expectedScope:pins.scope,expectedContext:context};
      if(guarded){serviceOptions.beforeDispatch=options.beforeDispatch;serviceOptions.beforePublish=options.beforePublish;}
      const result=await (method==='models' ? service.checkConnection(serviceOptions)
        : method==='learner-support' ? service.explainLearningSupport(incident,observation,serviceOptions)
          : service.explainIncident(incident,serviceOptions));
      alive();
      // Expiry during the remote operation also invalidates a successful result.
      if(Date.parse(v.expiresAt)<=Date.now())throw own('ON_AI_PROVISIONING_PENDING');
      if((method==='learner-support'||method==='models'&&options.beforeDispatch!==undefined||incidentCallbacks)&&result.ok===true){
        if(!Number.isSafeInteger(result.authorizationValidUntilMs))throw own('ON_AI_PROVISIONING_PENDING');
        const authorizationValidUntilMs=Math.floor(Math.min(result.authorizationValidUntilMs,Date.parse(v.expiresAt),deadline,Date.now()+Math.max(0,monotonicDeadline-performance.now())));
        if(authorizationValidUntilMs<=Date.now())throw own('ON_AI_PROVISIONING_PENDING');
        return {...result,authorizationValidUntilMs};
      }
      return result;
    };
    try {return await Promise.race([work(),stopped]);}
    catch(error){return failure(error);}
    finally {clearTimeout(timer);if(options.signal){if(guarded)Reflect.apply(EventTarget.prototype.removeEventListener,options.signal,['abort',cancel]);else options.signal.removeEventListener('abort',cancel);}controller.abort();}
  }
  return Object.freeze({
    connectionInfo:()=>({configured,authorized:false,authorizationRequired:true}),
    checkConnection:(options)=>operation('models',undefined,options),
    explainIncident:(input,options)=>operation('explain',input,options),
    explainLearningSupport:(input,observation,options)=>operation('learner-support',input,options,observation),
  });
}
