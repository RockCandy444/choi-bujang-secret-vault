import {createHash,randomBytes,randomUUID} from 'node:crypto';
import {createActionStore,existingDatabasePath} from './store.mjs';

const CKEYS=['subjectId','projectId','sessionId','identityVersion','appId','audience','accessPolicyId','engineGeneration','sourcePolicyVersion'];
const own=code=>Object.assign(new Error(code),{code});
const plain=v=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.getPrototypeOf(v)===Object.prototype;
const exact=(v,keys)=>plain(v)&&Reflect.ownKeys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const identifier=v=>typeof v==='string'&&/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$/.test(v);
const positive=v=>Number.isSafeInteger(v)&&v>0;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SECRET=/(?:Bearer\s+\S+|sk-[A-Za-z0-9_-]{8,}|-----BEGIN [A-Z ]*KEY-----|(?:password|secret|api[_ -]?key)\s*[:=]\s*\S+)/i;
const text=v=>typeof v==='string'&&v.length<=2000&&!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(v)&&!SECRET.test(v);
const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':plain(v)?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
const hash=v=>createHash('sha256').update(v).digest('hex');
const digest=v=>hash(canonical(v));
const freeze=v=>{if(v&&typeof v==='object'){for(const child of Object.values(v))freeze(child);Object.freeze(v);}return v;};
const target=v=>exact(v,['id','generation'])&&typeof v.id==='string'&&/^(?:subject|device):[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$/.test(v.id)&&positive(v.generation);
const context=v=>exact(v,CKEYS)&&CKEYS.filter(k=>!['identityVersion','engineGeneration'].includes(k)).every(k=>identifier(v[k]))
  &&positive(v.identityVersion)&&positive(v.engineGeneration)&&v.appId==='aleph-on'&&v.audience==='on-client';
const equals=(a,b)=>canonical(a)===canonical(b);
const eventKeys=['id','subjectId','projectId','kind','at','summary','evidence','rules','state','supportedActions','target'];
const event=v=>exact(v,eventKeys)&&['id','subjectId','projectId'].every(k=>identifier(v[k]))&&['access','xdr'].includes(v.kind)
  &&typeof v.at==='string'&&Number.isFinite(Date.parse(v.at))&&text(v.summary)&&target(v.target)
  &&['evidence','rules'].every(k=>Array.isArray(v[k])&&v[k].length<=20&&v[k].every(row=>exact(row,['id','text'])&&identifier(row.id)&&text(row.text))&&new Set(v[k].map(row=>row.id)).size===v[k].length)
  &&exact(v.state,['access','session','device'])&&['allowed','denied','unknown'].includes(v.state.access)&&['active','revoked','expired','unknown'].includes(v.state.session)&&['compliant','noncompliant','unknown'].includes(v.state.device)
  &&Array.isArray(v.supportedActions)&&v.supportedActions.length<=20&&v.supportedActions.every(identifier)&&new Set(v.supportedActions).size===v.supportedActions.length;

export function createActionService({engine,resolveContext,databasePath,policy,clock=Date.now}={}){
  // Unsupported setup must not open/create files or reinterpret a generic engine as authorized.
  const configured=plain(policy)&&Object.keys(policy).every(k=>['appId','audience','accessPolicyId','allowedActions','confirmationTtlMs','timeoutMs'].includes(k))&&policy.appId==='aleph-on'&&policy.audience==='on-client'&&identifier(policy.accessPolicyId)
    &&Array.isArray(policy.allowedActions)&&policy.allowedActions.length>0&&policy.allowedActions.length<=20&&policy.allowedActions.every(identifier)&&new Set(policy.allowedActions).size===policy.allowedActions.length
    &&positive(policy.confirmationTtlMs)&&positive(policy.timeoutMs??10000)&&typeof clock==='function'&&typeof resolveContext==='function'
    &&['demo','connected'].includes(engine?.evidenceMode)&&['readEvents','authorizeAction','executeAction','readActionResult'].every(k=>typeof engine[k]==='function')&&existingDatabasePath(databasePath);
  const settings=configured?freeze(structuredClone(policy)):null;
  const dispatcherId=randomUUID();let store;
  const mode=configured?engine.evidenceMode:'unsupported';
  const failure=code=>({ok:false,mode,error:{code,message:code==='ACTION_UNSUPPORTED'?'현재 이 조치는 지원하지 않습니다.':'조치 요청 또는 처리 결과를 확인할 수 없습니다.'}});
  const known=new Set(['ACTION_UNSUPPORTED','ACTION_INPUT_INVALID','ACTION_SCOPE_UNVERIFIED','ACTION_SCOPE_CHANGED','ACTION_EVENT_UNAVAILABLE','ACTION_DENIED','ACTION_SNAPSHOT_CHANGED','ACTION_CONFIRMATION_INVALID','ACTION_CONFIRMATION_EXPIRED','ACTION_STORE_FAILED','ACTION_TIMEOUT','ACTION_CANCELLED','ACTION_RESULT_UNVERIFIED']);
  const now=()=>{const value=clock();if(!positive(value)||!Number.isFinite(new Date(value).getTime()))throw own('ACTION_SCOPE_UNVERIFIED');return value;};
  const db=()=>store??(store=createActionStore({databasePath}));
  const current=async signal=>{
    if(signal.aborted)throw own('ACTION_CANCELLED');
    const value=freeze(structuredClone(await resolveContext({signal})));
    if(signal.aborted)throw own('ACTION_CANCELLED');if(!context(value)||value.accessPolicyId!==settings.accessPolicyId)throw own('ACTION_SCOPE_UNVERIFIED');return value;
  };
  const sameCurrent=async(scope,signal)=>{const latest=await current(signal);if(!equals(scope,latest))throw own('ACTION_SCOPE_CHANGED');};
  const readEvent=async(eventId,scope,signal)=>{
    const rows=structuredClone(await engine.readEvents(scope,{signal}));await sameCurrent(scope,signal);
    if(!Array.isArray(rows)||rows.length>500||rows.some(row=>!event(row)||row.subjectId!==scope.subjectId||row.projectId!==scope.projectId)||new Set(rows.map(row=>row.id)).size!==rows.length)throw own('ACTION_SCOPE_UNVERIFIED');
    const found=rows.find(row=>row.id===eventId);if(!found)throw own('ACTION_EVENT_UNAVAILABLE');return freeze(found);
  };
  const authorize=async(command,scope,signal)=>{
    const value=structuredClone(await engine.authorizeAction(command,scope,{signal}));await sameCurrent(scope,signal);
    if(!exact(value,['allowed','durableOperations','context','eventId','actionId','target','snapshotDigest'])||typeof value.allowed!=='boolean'||typeof value.durableOperations!=='boolean'
      ||!equals(value.context,scope)||value.eventId!==command.eventId||value.actionId!==command.actionId||!equals(value.target,command.target)||value.snapshotDigest!==command.snapshotDigest)throw own('ACTION_SCOPE_UNVERIFIED');
    if(!value.allowed)throw own('ACTION_DENIED');if(!value.durableOperations)throw own('ACTION_UNSUPPORTED');
  };
  const receipt=(row,replayed=false)=>({ok:true,mode,data:{requestId:row.request_id,receiptId:row.receipt_id,eventId:row.command.eventId,actionId:row.command.actionId,status:row.superseded?'unknown':row.status,version:row.version,replayed,...(row.superseded?{superseded:true}:row.result?{observation:row.result}:{})}});
  const bound=rowScope=>scope=>{if(!equals(rowScope,scope))throw own('ACTION_SCOPE_CHANGED');};
  async function operation(options,work){
    if(!configured)return failure('ACTION_UNSUPPORTED');
    const controller=new AbortController(),external=options?.signal,phase={requestId:null,reserved:false};let timer,cancel;
    const stopped=new Promise((_,reject)=>{
      cancel=()=>{controller.abort();reject(own('ACTION_CANCELLED'));};
      timer=setTimeout(()=>{controller.abort();reject(own('ACTION_TIMEOUT'));},settings.timeoutMs??10000);
      if(external?.aborted)cancel();else external?.addEventListener('abort',cancel,{once:true});
    });
    try{return await Promise.race([work(controller.signal,phase),stopped]);}
    catch(error){
      const code=known.has(error?.code)?error.code:'ACTION_RESULT_UNVERIFIED';
      if(phase.reserved){
        const scopeFailure=['ACTION_SCOPE_UNVERIFIED','ACTION_SCOPE_CHANGED','ACTION_EVENT_UNAVAILABLE','ACTION_DENIED','ACTION_SNAPSHOT_CHANGED','ACTION_UNSUPPORTED'].includes(code);
        try{const row=db().transition({requestId:phase.requestId,status:'unknown',code,at:now(),allowStates:phase.resultRead?undefined:['reserved','pending'],expectedVersion:phase.resultVersion});if(scopeFailure)return failure(code);if(row)return receipt(row);}catch{}
        if(scopeFailure)return failure(code);return {ok:true,mode,data:{requestId:phase.requestId,status:'unknown'}};
      }
      return failure(code);
    }finally{clearTimeout(timer);external?.removeEventListener('abort',cancel);controller.abort();}
  }
  const load=async(requestId,signal)=>{const scope=await current(signal),row=db().get(requestId);if(!row)throw own('ACTION_EVENT_UNAVAILABLE');bound(row.scope)(scope);row.command=freeze(structuredClone(row.command));row.scope=freeze(structuredClone(row.scope));return {scope,row};};
  // 결과 DTO 검증·기록. bindScope 는 결과가 결속돼야 하는 원 scope 다(일반 경로는 현재와 같은 scope, 영수증 경로는 원 row.scope).
  const settle=(row,result,bindScope)=>{
    const command=row.command;
    const valid=exact(result,['requestId','fingerprint','scope','eventId','actionId','target','snapshotDigest','status','observedAt','effect'])
      &&['requestId','fingerprint','eventId','actionId','snapshotDigest'].every(k=>result[k]===command[k])&&equals(result.scope,bindScope)&&equals(result.target,command.target)
      &&['pending','succeeded','denied','failed','unknown'].includes(result.status)&&typeof result.observedAt==='string'&&Number.isFinite(Date.parse(result.observedAt))
      &&Date.parse(result.observedAt)>=row.created_at_ms&&Date.parse(result.observedAt)<=now()
      &&(result.effect===null||exact(result.effect,['applied','operationId','target','snapshotDigest'])&&typeof result.effect.applied==='boolean'&&result.effect.operationId===command.requestId&&equals(result.effect.target,command.target)&&result.effect.snapshotDigest===command.snapshotDigest)
      &&(result.status!=='succeeded'||result.effect?.applied===true);
    const status=valid?result.status:'unknown';
    const observation=valid?{observedAt:new Date(Date.parse(result.observedAt)).toISOString(),effectApplied:result.effect?.applied===true}:null;
    return receipt(db().transition({requestId:row.request_id,status,code:valid?'ACTION_RESULT_OBSERVED':'ACTION_RESULT_UNVERIFIED',at:now(),result:observation,expectedVersion:row.version}));
  };
  // 소비된 operation 의 영수증 읽기(C2-R2b, #955). 게시 뒤에는 session·sourcePolicyVersion·target generation 이 바뀌므로
  // 일반 load(9필드 동일성)·fresh(사건 재조회·authorize)를 거치지 않는다. 대신 원 9필드 scope·command·fingerprint·digest 를 불변 증거로 두고,
  // 현재 principal 은 원 scope 와 subject·project·appId·audience·accessPolicyId 가 같아야 한다. 재승인·재게시·일반 사건 권한 재개는 없다.
  // 엔진이 readActionReceipt 를 제공할 때만 쓴다(없으면 기존 경로). prepare·execute 의 검사는 그대로다.
  const PRINCIPAL=['subjectId','projectId','appId','audience','accessPolicyId'];
  async function consumedReceipt(requested,signal,phase){
    const row=db().get(requested.requestId);
    if(!row||row.confirmation_consumed!==1)throw own('ACTION_EVENT_UNAVAILABLE');
    row.command=freeze(structuredClone(row.command));row.scope=freeze(structuredClone(row.scope));
    // c1(#968): 이 기기를 스스로 철회한 뒤에는 현재 SDP context 를 읽을 수 없다. 그 경우에만(device:revoke, 엔진이 제공할 때)
    // 본인 영수증 경로로 읽는다. 주체 확인은 SDP 영수증 listener(철회 기기 인증서=대상)·gateway(native canonical4)·host(native project)가 한다.
    let latest;
    try{latest=await current(signal);}
    catch(error){
      if(signal.aborted||row.command.actionId!=='device:revoke'||typeof engine.readOwnRevokedReceipt!=='function')throw error;
      phase.requestId=requested.requestId;phase.reserved=true;phase.resultRead=true;phase.resultVersion=row.version;
      let ownReceipt;
      try{ownReceipt=structuredClone(await engine.readOwnRevokedReceipt({requestId:requested.requestId},row.scope,{signal}));}
      catch(failure){if(signal.aborted)throw failure;return receipt(db().transition({requestId:requested.requestId,status:'unknown',code:'ACTION_RESULT_UNVERIFIED',at:now(),expectedVersion:row.version}));}
      return settle(row,ownReceipt,row.scope);
    }
    const samePrincipal=value=>PRINCIPAL.every(k=>value[k]===row.scope[k]);
    if(!samePrincipal(latest))throw own('ACTION_SCOPE_CHANGED');
    phase.requestId=requested.requestId;phase.reserved=true;phase.resultRead=true;phase.resultVersion=row.version;
    let result;
    try{result=structuredClone(await engine.readActionReceipt({requestId:requested.requestId},row.scope,{signal}));if(!samePrincipal(await current(signal)))throw own('ACTION_SCOPE_CHANGED');}
    catch(error){if(error?.code==='ACTION_SCOPE_CHANGED'||signal.aborted)throw error;return receipt(db().transition({requestId:requested.requestId,status:'unknown',code:'ACTION_RESULT_UNVERIFIED',at:now(),expectedVersion:row.version}));}
    return settle(row,result,row.scope);
  }
  const fresh=async(row,scope,signal)=>{
    const found=await readEvent(row.command.eventId,scope,signal);
    if(digest(found)!==row.command.snapshotDigest)throw own('ACTION_SNAPSHOT_CHANGED');
    if(!found.supportedActions.includes(row.command.actionId)||!settings.allowedActions.includes(row.command.actionId))throw own('ACTION_DENIED');
    await authorize(row.command,scope,signal);return found;
  };
  return Object.freeze({
    prepare(input,options={}){return operation(options,async signal=>{
      if(!exact(input,['eventId','actionId'])||!identifier(input.eventId)||!identifier(input.actionId))throw own('ACTION_INPUT_INVALID');
      const requested=freeze(structuredClone(input)),scope=await current(signal),found=await readEvent(requested.eventId,scope,signal);
      if(!settings.allowedActions.includes(requested.actionId)||!found.supportedActions.includes(requested.actionId))throw own('ACTION_DENIED');
      const requestId=randomUUID(),snapshotDigest=digest(found),base={requestId,scope,eventId:found.id,actionId:requested.actionId,target:found.target,snapshotDigest};
      const command=freeze({...base,fingerprint:digest({schema:'alekov.action.intent.v1',...base})});await authorize(command,scope,signal);
      if(signal.aborted)throw own('ACTION_CANCELLED');const at=now(),expiresAtMs=at+settings.confirmationTtlMs;
      if(!Number.isSafeInteger(expiresAtMs)||!Number.isFinite(new Date(expiresAtMs).getTime()))throw own('ACTION_UNSUPPORTED');
      const confirmationId='ac-on-'+randomBytes(32).toString('base64url');
      const row=db().insert({requestId,receiptId:randomUUID(),scope,command,confirmationHash:hash('alekov.action.confirmation\0'+confirmationId),expiresAtMs,at});
      return {...receipt(row),data:{...receipt(row).data,confirmationId,confirmationExpiresAt:new Date(expiresAtMs).toISOString(),snapshotDigest,target:found.target}};
    });},
    execute(input,options={}){return operation(options,async(signal,phase)=>{
      if(!exact(input,['requestId','confirmationId'])||!UUID.test(input.requestId)||typeof input.confirmationId!=='string'||!/^ac-on-[A-Za-z0-9_-]{43}$/.test(input.confirmationId))throw own('ACTION_CONFIRMATION_INVALID');
      const requested=freeze(structuredClone(input)),{scope,row}=await load(requested.requestId,signal);await fresh(row,scope,signal);
      if(signal.aborted)throw own('ACTION_CANCELLED');
      const reserved=db().reserve({requestId:requested.requestId,confirmationHash:hash('alekov.action.confirmation\0'+requested.confirmationId),dispatcherId,at:now()});
      if(!reserved.reserved){
        const old=reserved.row;
        if(old.dispatcher_id!==dispatcherId&&['reserved','pending'].includes(old.status))return receipt(db().transition({requestId:old.request_id,status:'unknown',code:'ACTION_RESTART_RECONCILE',at:now(),allowStates:['reserved','pending']}),true);
        return receipt(old,true);
      }
      phase.requestId=requested.requestId;phase.reserved=true;
      if(signal.aborted)throw own('ACTION_CANCELLED');
      const acknowledgment=structuredClone(await engine.executeAction(row.command,scope,{signal}));await sameCurrent(scope,signal);
      // A transport ACK is never effect proof. Only readResult may report succeeded.
      const status=exact(acknowledgment,['status'])&&acknowledgment.status==='denied'?'denied':exact(acknowledgment,['status'])&&acknowledgment.status==='accepted'?'pending':'unknown';
      return receipt(db().transition({requestId:requested.requestId,status,code:'ACTION_DISPATCH_ACK',at:now(),allowStates:['reserved']}));
    });},
    readResult(input,options={}){return operation(options,async(signal,phase)=>{
      if(!exact(input,['requestId'])||!UUID.test(input.requestId))throw own('ACTION_INPUT_INVALID');
      const requested=freeze(structuredClone(input)),stored=db().get(requested.requestId);
      if(stored?.confirmation_consumed===1&&typeof engine.readActionReceipt==='function')return consumedReceipt(requested,signal,phase);
      const {scope,row}=await load(requested.requestId,signal);
      phase.requestId=requested.requestId;phase.reserved=row.confirmation_consumed===1;phase.resultRead=true;phase.resultVersion=row.version;await fresh(row,scope,signal);
      if(!row.confirmation_consumed)return receipt(row);
      let result;
      try{result=structuredClone(await engine.readActionResult({requestId:requested.requestId},scope,{signal}));await sameCurrent(scope,signal);}
      catch(error){if(error?.code==='ACTION_SCOPE_CHANGED'||signal.aborted)throw error;return receipt(db().transition({requestId:requested.requestId,status:'unknown',code:'ACTION_RESULT_UNVERIFIED',at:now(),expectedVersion:row.version}));}
      return settle(row,result,scope);
    });},
  });
}
