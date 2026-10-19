// 실제 SDP admission endpoint만 호출하는 서버 전용 엔진. 설정/비밀은 브라우저 DTO로 반환하지 않는다.
import {types} from 'node:util';
import {createHash,randomUUID} from 'node:crypto';
import {getSdpHostProjectId,captureSdpHostCredentials,verifySdpHostCredentials,closeSdpHostCredentials,postSdpHostAdmission,sdpHostError,sdpHostRecord,sdpHostSignal,
  postSdpHostOwnReceipt,sdpHostReceiptEnabled} from './sdp-host-config.mjs';
import {isNativeHostContext,openNativeHostOperation,issueNativeHostReceipt,assertNativeHostOperation,closeNativeHostOperation} from '../connection/native-context.mjs';

const engines=new WeakMap(),incidentOperations=new WeakMap();
const TIMEOUT_MS=5000,CLOCK_SKEW_MS=5000;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/;
const SUBJECT=/^[0-9a-f]{64}$/;
const OBSERVATION=Object.freeze({
  events:Object.freeze({scope:'own-recorded-events',limit:40}),
  devices:Object.freeze({scope:'own-registered-devices',limit:100}),
  sessions:Object.freeze({scope:'current-verified-connection',limit:1}),
});
const RULE=/^[a-z][a-z0-9_.-]{0,63}$/;
const CONTEXT_KEYS=['subjectId','projectId','classId','deviceId','sessionId','policyRevision','registryDigest','catalogDigest','observedAtMs','validUntilMs','deviceStatus'];
const GENERATION_KEYS=['subjectId','projectId','classId','deviceId','sessionId','policyRevision','registryDigest','catalogDigest','deviceStatus'];
const positiveMs=value=>Number.isSafeInteger(value)&&value>0;
const safeName=value=>typeof value==='string'&&[...value].length>=1&&[...value].length<=80&&!/[\x00-\x1f\x7f-\x9f\u2028\u2029]/.test(value);
const match=(pattern,value)=>typeof value==='string'&&pattern.test(value);
const scopeError=()=>{throw sdpHostError('SUBJECT_SCOPE_UNVERIFIED');};
const resultError=()=>{throw sdpHostError('ENGINE_RESULT_UNVERIFIED');};
function checkContext(value,operation,receivedAtMs){
  const c=sdpHostRecord(value,CONTEXT_KEYS);
  if(!match(SUBJECT,c.subjectId)||typeof c.projectId!=='string'||!/^[a-z][a-z0-9_-]{0,63}$/.test(c.projectId)||!match(ID,c.classId)||!match(/^[0-9a-f]{16}$/,c.deviceId)
    ||!match(ID,c.sessionId)||!Number.isSafeInteger(c.policyRevision)||c.policyRevision<0||!match(SUBJECT,c.registryDigest)||!match(SUBJECT,c.catalogDigest)
    ||c.deviceStatus!=='unknown'||!positiveMs(c.observedAtMs)||!positiveMs(c.validUntilMs)||!positiveMs(receivedAtMs)
    ||c.validUntilMs<=c.observedAtMs||c.validUntilMs-c.observedAtMs>10000||c.observedAtMs<operation.startedAtMs-CLOCK_SKEW_MS||c.observedAtMs>receivedAtMs+CLOCK_SKEW_MS)resultError();
  if(c.projectId!==operation.projectId)scopeError();
  assertFresh(c);return c;
}
function assertFresh(context){if(context.validUntilMs<=Date.now())throw sdpHostError('SUBJECT_SCOPE_UNVERIFIED');}
function sameGeneration(previous,current){if(GENERATION_KEYS.some(key=>previous[key]!==current[key]))scopeError();}
function readScope(raw,projectId){const scope=sdpHostRecord(raw,['subjectId','projectId','appId','audience']);if(!match(SUBJECT,scope.subjectId)||scope.projectId!==projectId||scope.appId!=='aleph-on'||scope.audience!=='on-client')scopeError();return scope;}
function sameScope(scope,context){if(scope.subjectId!==context.subjectId||scope.projectId!==context.projectId)scopeError();}
function envelope(reply,kind,operation){
  const keys=['schema','kind','engineRequestId','context'];if(kind!=='context')keys.push(DATA_KEY[kind]??kind);if(Object.hasOwn(OBSERVATION,kind)||kind==='action-events')keys.push('coverage');
  const data=sdpHostRecord(reply.data,keys);
  if(data.schema!=='alekov.sdp.admission.v1'||data.kind!==kind||!match(UUID,data.engineRequestId)||!match(UUID,reply.engineRequestId)||data.engineRequestId!==reply.engineRequestId)resultError();
  return {data,context:checkContext(data.context,operation,reply.receivedAtMs),receivedAtMs:reply.receivedAtMs};
}
function makeOperation(state,call,timeoutMs=TIMEOUT_MS){
  const options=sdpHostRecord(call,[],['signal']),external=sdpHostSignal(options.signal);
  if(state.closed)throw sdpHostError('ENGINE_NOT_CONNECTED');if(external?.aborted)throw sdpHostError('REQUEST_CANCELLED');
  const controller=new AbortController(),startedAtMs=Date.now(),startedMono=performance.now();
  const operation={projectId:state.projectId,startedAtMs,controller,snapshot:null,contexts:[],error:null,timer:null,closed:false};
  const stop=code=>{if(operation.closed||operation.error)return;operation.error=sdpHostError(code);controller.abort();};
  const onAbort=()=>stop('REQUEST_CANCELLED');
  operation.assertAlive=()=>{
    if(operation.error)throw operation.error;
    if(state.closed||external?.aborted||controller.signal.aborted){stop('REQUEST_CANCELLED');throw operation.error;}
    if(Date.now()>=startedAtMs+timeoutMs||performance.now()>=startedMono+timeoutMs){stop('ENGINE_TIMEOUT');throw operation.error;}
  };
  operation.close=()=>{if(operation.closed)return;operation.closed=true;clearTimeout(operation.timer);external?.removeEventListener('abort',onAbort);controller.abort();closeSdpHostCredentials(operation.snapshot);state.operations.delete(operation);};
  operation.cancel=()=>stop('REQUEST_CANCELLED');
  state.operations.add(operation);external?.addEventListener('abort',onAbort,{once:true});operation.timer=setTimeout(()=>stop('ENGINE_TIMEOUT'),timeoutMs);
  try{operation.assertAlive();operation.snapshot=captureSdpHostCredentials(state.configuration);operation.assertAlive();return operation;}catch(error){operation.close();throw error;}
}
async function execute(state,call,work,timeoutMs=TIMEOUT_MS){
  let operation;
  try{operation=makeOperation(state,call,timeoutMs);const result=await work(operation);finalCheck(operation,operation.contexts);return result;}
  catch(error){if(operation?.error)throw operation.error;
    if(error&&typeof error==='object'&&!types.isProxy(error)){const code=Object.getOwnPropertyDescriptor(error,'code');if(code&&Object.hasOwn(code,'value'))throw sdpHostError(code.value);}
    throw sdpHostError('ENGINE_NOT_CONNECTED');
  }finally{operation?.close();}
}
function base(operation){return {appId:'aleph-on',audience:'on-client',projectId:operation.projectId};}
async function readEndpoint(operation,kind,body){
  operation.assertAlive();verifySdpHostCredentials(operation.snapshot);operation.assertAlive();
  const requestedAtMs=Date.now(),reply=await postSdpHostAdmission(operation.snapshot,kind,body,{signal:operation.controller.signal});
  operation.assertAlive();const output=envelope(reply,kind,operation.privateIncident?{...operation,startedAtMs:requestedAtMs}:operation);verifySdpHostCredentials(operation.snapshot);operation.assertAlive();assertFresh(output.context);operation.contexts.push(output.context);return output;
}
function finalCheck(operation,contexts){
  operation.assertAlive();verifySdpHostCredentials(operation.snapshot);operation.assertAlive();for(const context of contexts)assertFresh(context);
}
const observationText=(value,max)=>typeof value==='string'&&[...value].length>=1&&[...value].length<=max&&!/[\x00-\x1f\x7f-\x9f\u2028\u2029]/.test(value);
function canonicalEventTime(value){
  if(typeof value!=='string')return false;const parsed=Date.parse(value);
  return Number.isSafeInteger(parsed)&&new Date(parsed).toISOString()===value;
}
function observationCoverage(raw,kind,rows,operation,response){
  const coverage=sdpHostRecord(raw,['schema','kind','scope','limit','total','returned','truncated','observedAtMs']),expected=OBSERVATION[kind];
  if(coverage.schema!=='alekov.sdp.coverage.v1'||coverage.kind!==kind||coverage.scope!==expected.scope||coverage.limit!==expected.limit
    ||!Number.isSafeInteger(coverage.total)||coverage.total<0||!Number.isSafeInteger(coverage.returned)||coverage.returned<0
    ||coverage.returned!==rows.length||coverage.returned>expected.limit||coverage.total<coverage.returned
    ||typeof coverage.truncated!=='boolean'||coverage.truncated!==(coverage.total>coverage.returned)
    ||!positiveMs(coverage.observedAtMs)||coverage.observedAtMs<operation.startedAtMs-CLOCK_SKEW_MS||coverage.observedAtMs>response.receivedAtMs+CLOCK_SKEW_MS
    ||Math.abs(coverage.observedAtMs-response.context.observedAtMs)>10000||coverage.observedAtMs>=response.context.validUntilMs)resultError();
  if(kind==='sessions'&&(coverage.total!==1||coverage.returned!==1||coverage.truncated))resultError();
  return Object.freeze({schema:coverage.schema,kind:coverage.kind,scope:coverage.scope,limit:coverage.limit,total:coverage.total,returned:coverage.returned,truncated:coverage.truncated,observedAtMs:coverage.observedAtMs});
}
function observationEvidence(raw){
  if(!Array.isArray(raw)||raw.length>8)resultError();const seen=new Set(),rows=[];
  for(const item of raw){const row=sdpHostRecord(item,['id','text']);if(!match(ID,row.id)||!observationText(row.text,500)||seen.has(row.id))resultError();seen.add(row.id);rows.push(Object.freeze({id:row.id,text:row.text}));}
  return Object.freeze(rows);
}
function observationEvents(raw,scope){
  const ids=new Set(),rows=[];
  for(const item of raw){
    const event=sdpHostRecord(item,['id','kind','at','appId','summary','evidence','rules','state','supportedActions','subjectId','projectId']);
    if(!match(ID,event.id)||ids.has(event.id)||!['access','xdr'].includes(event.kind)||!canonicalEventTime(event.at)
      ||event.appId!==null&&!match(ID,event.appId)||!observationText(event.summary,200)||!Array.isArray(event.supportedActions)||event.supportedActions.length!==0)resultError();
    if(event.subjectId!==scope.subjectId||event.projectId!==scope.projectId)scopeError();
    const status=sdpHostRecord(event.state,['access','session','device']);
    if(!['allowed','denied','unknown'].includes(status.access)||status.session!=='unknown'||status.device!=='unknown')resultError();
    ids.add(event.id);rows.push(Object.freeze({id:event.id,kind:event.kind,at:event.at,appId:event.appId,summary:event.summary,
      evidence:observationEvidence(event.evidence),rules:observationEvidence(event.rules),state:Object.freeze({access:status.access,session:'unknown',device:'unknown'}),
      supportedActions:Object.freeze([]),subjectId:event.subjectId,projectId:event.projectId}));
  }
  return rows;
}
function observationDevices(raw,scope,context){
  const ids=new Set(),rows=[];
  for(const item of raw){const device=sdpHostRecord(item,['id','label','status','subjectId','projectId']);
    if(!match(/^[0-9a-f]{16}$/,device.id)||ids.has(device.id)||device.label!=='등록된 기기'||device.status!=='unknown')resultError();
    if(device.subjectId!==scope.subjectId||device.projectId!==scope.projectId)scopeError();ids.add(device.id);
    rows.push(Object.freeze({id:device.id,label:'등록된 기기',status:'unknown',subjectId:device.subjectId,projectId:device.projectId}));
  }
  // 잘린 목록이어도 현재 인증 기기를 확인할 수 있어야 한다. 빠지면 빈 성공으로 바꾸지 않는다.
  if(!ids.has(context.deviceId))scopeError();return rows;
}
function observationSessions(raw,scope,context){
  if(raw.length!==1)resultError();const session=sdpHostRecord(raw[0],['id','status','subjectId','projectId']);
  if(session.id!==context.sessionId||session.subjectId!==scope.subjectId||session.projectId!==scope.projectId)scopeError();
  if(session.status!=='active')resultError();return [Object.freeze({id:session.id,status:'active',subjectId:session.subjectId,projectId:session.projectId})];
}
function readObservation(state,kind,rawScope,call){return execute(state,call,async operation=>{
  const scope=readScope(rawScope,state.projectId),before=await readEndpoint(operation,'context',base(operation));sameScope(scope,before.context);
  const after=await readEndpoint(operation,kind,{...base(operation),sessionId:before.context.sessionId});sameGeneration(before.context,after.context);sameScope(scope,after.context);
  const source=after.data[kind];if(!Array.isArray(source)||source.length>OBSERVATION[kind].limit)resultError();
  const coverage=observationCoverage(after.data.coverage,kind,source,operation,after);
  const rows=kind==='events'?observationEvents(source,scope):kind==='devices'?observationDevices(source,scope,after.context):observationSessions(source,scope,after.context);
  Object.defineProperty(rows,'coverage',{value:coverage,enumerable:false,writable:false,configurable:false});return Object.freeze(rows);
});}
// ── 19단계 조치 (C2-R2b SOURCE, 운영 비활성) ─────────────────────────────────────────
// 학생 모듈에 넘기는 hostCapability 에는 넣지 않는다. host 소유 src/actions/sdp-action-engine.mjs 만 쓴다.
// 공개 readEvents(9필드 투영·supportedActions [])와 별개로, relay 조치 전용 경로의 service 11필드 행을 읽는다.
const DATA_KEY=Object.freeze({'ai-binding':'binding','action-context':'actionContext','action-events':'events','action-authorize':'authorization','action-execute':'acknowledgment','action-result':'result'});
const ACTION_SCOPE_KEYS=['subjectId','projectId','sessionId','identityVersion','appId','audience','accessPolicyId','engineGeneration','sourcePolicyVersion'];
const ACTION_COMMAND_KEYS=['requestId','scope','eventId','actionId','target','snapshotDigest','fingerprint'];
const ACTIONS=['device:revoke','grant:remove'];
const SCOPE_ID=/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$/;
const TARGET=/^(?:subject|device):[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$/;
const HASH64=/^[0-9a-f]{64}$/;
const SDP_EVENT=/^sdp-[0-9a-f]{32}$/;
function readActionScope(raw,projectId){
  const s=sdpHostRecord(raw,ACTION_SCOPE_KEYS);
  if(!match(SUBJECT,s.subjectId)||s.projectId!==projectId||s.appId!=='aleph-on'||s.audience!=='on-client'||!match(ID,s.sessionId)||!positiveMs(s.identityVersion)
    ||!positiveMs(s.engineGeneration)||!match(SCOPE_ID,s.accessPolicyId)||!match(/^(?:0|[1-9][0-9]{0,14})$/,s.sourcePolicyVersion))scopeError();
  return s;
}
const plainScope=s=>Object.fromEntries(ACTION_SCOPE_KEYS.map(key=>[key,s[key]]));
const sameScopeValues=(a,b)=>ACTION_SCOPE_KEYS.every(key=>a[key]===b[key]);
// 현재 relay context 가 scope 의 SDP 부분(subject·project·session·정책 revision)과 같아야 한다.
function sameActionScope(scope,context){if(scope.subjectId!==context.subjectId||scope.projectId!==context.projectId||scope.sessionId!==context.sessionId||scope.sourcePolicyVersion!==String(context.policyRevision))scopeError();}
// 영수증 읽기의 현재 principal: subject·project 만 같으면 된다(게시 뒤 session·정책 revision 은 바뀐다).
function samePrincipal(scope,context){if(scope.subjectId!==context.subjectId||scope.projectId!==context.projectId)scopeError();}
function actionTarget(raw){const t=sdpHostRecord(raw,['id','generation']);if(!match(TARGET,t.id)||!positiveMs(t.generation))resultError();return Object.freeze({id:t.id,generation:t.generation});}
function actionCommand(raw,scope){
  const c=sdpHostRecord(raw,ACTION_COMMAND_KEYS),bound=sdpHostRecord(c.scope,ACTION_SCOPE_KEYS),target=actionTarget(c.target);
  if(!match(UUID,c.requestId)||!match(SDP_EVENT,c.eventId)||!ACTIONS.includes(c.actionId)||!match(HASH64,c.snapshotDigest)||!match(HASH64,c.fingerprint)||!sameScopeValues(bound,scope))scopeError();
  return Object.freeze({requestId:c.requestId,eventId:c.eventId,actionId:c.actionId,target,snapshotDigest:c.snapshotDigest,fingerprint:c.fingerprint});
}
const actionInput=c=>({requestId:c.requestId,eventId:c.eventId,actionId:c.actionId,targetId:c.target.id,targetGeneration:String(c.target.generation),snapshotDigest:c.snapshotDigest});
function actionEvents(raw,scope){
  const ids=new Set(),rows=[];
  for(const item of raw){
    const e=sdpHostRecord(item,['id','subjectId','projectId','kind','at','summary','evidence','rules','state','supportedActions','target']);
    if(!match(ID,e.id)||ids.has(e.id)||!['access','xdr'].includes(e.kind)||!canonicalEventTime(e.at)||!observationText(e.summary,200)
      ||!Array.isArray(e.supportedActions)||e.supportedActions.length>ACTIONS.length||e.supportedActions.some(a=>!ACTIONS.includes(a))||new Set(e.supportedActions).size!==e.supportedActions.length)resultError();
    if(e.subjectId!==scope.subjectId||e.projectId!==scope.projectId)scopeError();
    const status=sdpHostRecord(e.state,['access','session','device']);
    if(!['allowed','denied','unknown'].includes(status.access)||status.session!=='unknown'||status.device!=='unknown')resultError();
    const target=actionTarget(e.target);
    if(e.supportedActions.length===0&&target.id!=='subject:'+scope.subjectId)resultError(); // 미지원 행은 본인 범위 target 만
    ids.add(e.id);rows.push({id:e.id,subjectId:e.subjectId,projectId:e.projectId,kind:e.kind,at:e.at,summary:e.summary,
      evidence:observationEvidence(e.evidence).map(r=>({id:r.id,text:r.text})),rules:observationEvidence(e.rules).map(r=>({id:r.id,text:r.text})),
      state:{access:status.access,session:'unknown',device:'unknown'},supportedActions:[...e.supportedActions],target:{id:target.id,generation:target.generation}});
  }
  return rows;
}
function actionReceipt(raw,input,scope){
  const r=sdpHostRecord(raw,['requestId','fingerprint','scope','eventId','actionId','target','snapshotDigest','status','observedAt','effect']);
  const bound=sdpHostRecord(r.scope,ACTION_SCOPE_KEYS),target=actionTarget(r.target);
  if(r.requestId!==input.requestId||!sameScopeValues(bound,scope))scopeError();
  if(!match(HASH64,r.fingerprint)||!match(SDP_EVENT,r.eventId)||!ACTIONS.includes(r.actionId)||!match(HASH64,r.snapshotDigest)
    ||!['pending','succeeded','denied','failed','unknown'].includes(r.status)||!canonicalEventTime(r.observedAt))resultError();
  let effect=null;
  if(r.effect!==null){const f=sdpHostRecord(r.effect,['applied','operationId','target','snapshotDigest']),t=actionTarget(f.target);
    if(typeof f.applied!=='boolean'||f.operationId!==r.requestId||t.id!==target.id||t.generation!==target.generation||f.snapshotDigest!==r.snapshotDigest)resultError();
    effect={applied:f.applied,operationId:f.operationId,target:{id:t.id,generation:t.generation},snapshotDigest:f.snapshotDigest};}
  if(r.status==='succeeded'&&effect?.applied!==true)resultError();
  return {requestId:r.requestId,fingerprint:r.fingerprint,scope:plainScope(bound),eventId:r.eventId,actionId:r.actionId,target:{id:target.id,generation:target.generation},
    snapshotDigest:r.snapshotDigest,status:r.status,observedAt:r.observedAt,effect};
}
export function createSdpHostEngine(configuration){
  const projectId=getSdpHostProjectId(configuration),state={configuration,projectId,closed:false,operations:new Set()};
  const api=Object.freeze({
    evidenceMode:'connected',projectId,
    async readIdentity(call={}){return execute(state,call,async operation=>{
      const current=await readEndpoint(operation,'context',base(operation)),context=current.context;
      const result=Object.freeze({user:Object.freeze({id:context.subjectId,label:'확인된 사용자'}),device:Object.freeze({id:context.deviceId,label:'현재 기기',status:'unknown'}),session:Object.freeze({id:context.sessionId,status:'active'})});
      return result;
    });},
    async readApps(rawScope,call={}){return execute(state,call,async operation=>{
      const scope=readScope(rawScope,projectId),before=await readEndpoint(operation,'context',base(operation));sameScope(scope,before.context);
      const after=await readEndpoint(operation,'apps',{...base(operation),sessionId:before.context.sessionId});sameGeneration(before.context,after.context);sameScope(scope,after.context);
      const apps=after.data.apps;if(!Array.isArray(apps)||apps.length>100)resultError();const ids=new Set(),result=[];
      for(const value of apps){const app=sdpHostRecord(value,['id','name','subjectId','projectId']);if(!match(ID,app.id)||!safeName(app.name)||ids.has(app.id))resultError();if(app.subjectId!==scope.subjectId||app.projectId!==scope.projectId)scopeError();ids.add(app.id);result.push(Object.freeze({id:app.id,name:app.name,subjectId:app.subjectId,projectId:app.projectId}));}
      return Object.freeze(result);
    });},
    async decideAccess(rawInput,rawScope,call={}){return execute(state,call,async operation=>{
      const input=sdpHostRecord(rawInput,['appId','requestId']),scope=readScope(rawScope,projectId);if(!match(ID,input.appId)||!match(UUID,input.requestId))resultError();
      const before=await readEndpoint(operation,'context',base(operation));sameScope(scope,before.context);
      const after=await readEndpoint(operation,'decision',{...base(operation),sessionId:before.context.sessionId,targetAppId:input.appId,clientRequestId:input.requestId});sameGeneration(before.context,after.context);sameScope(scope,after.context);
      const decision=sdpHostRecord(after.data.decision,['appId','clientRequestId','engineRequestId','decision','reason','ruleIds','checkedAt','subjectId','projectId','sessionId']);
      if(decision.appId!==input.appId||decision.clientRequestId!==input.requestId||decision.engineRequestId!==after.data.engineRequestId||decision.subjectId!==scope.subjectId||decision.projectId!==scope.projectId||decision.sessionId!==before.context.sessionId)scopeError();
      if(!['allow','deny','challenge'].includes(decision.decision)||!match(RULE,decision.reason)||!Array.isArray(decision.ruleIds)||decision.ruleIds.length>8||(decision.decision!=='allow'&&decision.ruleIds.length===0)||decision.ruleIds.some(rule=>!match(RULE,rule))||new Set(decision.ruleIds).size!==decision.ruleIds.length)resultError();
      const checkedAtMs=typeof decision.checkedAt==='string'?Date.parse(decision.checkedAt):NaN;
      if(!positiveMs(checkedAtMs)||new Date(checkedAtMs).toISOString()!==decision.checkedAt||checkedAtMs<operation.startedAtMs-CLOCK_SKEW_MS||checkedAtMs>after.receivedAtMs+CLOCK_SKEW_MS||checkedAtMs>=after.context.validUntilMs)resultError();
      const result=Object.freeze({appId:input.appId,decision:decision.decision,reason:'접근 판정: '+decision.reason,checkedAt:decision.checkedAt,subjectId:scope.subjectId,projectId,requestId:input.requestId});
      return result;
    });},
    readEvents(scope,call={}){return readObservation(state,'events',scope,call);},
    // 조치 context 의 relay 부분(identityVersion 제외). host 소유 resolver 가 native 결속의 identityVersion 을 더한다.
    async readActionContext(call={}){return execute(state,call,async operation=>{
      const before=await readEndpoint(operation,'context',base(operation));
      const after=await readEndpoint(operation,'action-context',{...base(operation),sessionId:before.context.sessionId});sameGeneration(before.context,after.context);
      const value=sdpHostRecord(after.data.actionContext,['accessPolicyId','engineGeneration']);if(!match(SCOPE_ID,value.accessPolicyId)||!positiveMs(value.engineGeneration))resultError();
      const c=after.context;
      return Object.freeze({subjectId:c.subjectId,projectId:c.projectId,sessionId:c.sessionId,accessPolicyId:value.accessPolicyId,engineGeneration:value.engineGeneration,sourcePolicyVersion:String(c.policyRevision)});
    });},
    async readActionEvents(rawScope,call={}){return execute(state,call,async operation=>{
      const scope=readActionScope(rawScope,projectId),before=await readEndpoint(operation,'context',base(operation));sameActionScope(scope,before.context);
      const after=await readEndpoint(operation,'action-events',{...base(operation),sessionId:before.context.sessionId});sameGeneration(before.context,after.context);sameActionScope(scope,after.context);
      const source=after.data.events;if(!Array.isArray(source)||source.length>OBSERVATION.events.limit)resultError();
      const coverage=observationCoverage(after.data.coverage,'events',source,operation,after),rows=actionEvents(source,scope);
      Object.defineProperty(rows,'coverage',{value:coverage,enumerable:false,writable:false,configurable:false});return rows;
    });},
    async authorizeAction(rawCommand,rawScope,call={}){return execute(state,call,async operation=>{
      const scope=readActionScope(rawScope,projectId),command=actionCommand(rawCommand,scope),before=await readEndpoint(operation,'context',base(operation));sameActionScope(scope,before.context);
      const after=await readEndpoint(operation,'action-authorize',{...base(operation),sessionId:before.context.sessionId,...actionInput(command)});sameGeneration(before.context,after.context);sameActionScope(scope,after.context);
      const a=sdpHostRecord(after.data.authorization,['allowed','durableOperations','requestId','eventId','actionId','target','snapshotDigest']),target=actionTarget(a.target);
      if(typeof a.allowed!=='boolean'||typeof a.durableOperations!=='boolean'||a.requestId!==command.requestId||a.eventId!==command.eventId||a.actionId!==command.actionId
        ||a.snapshotDigest!==command.snapshotDigest||target.id!==command.target.id||target.generation!==command.target.generation)resultError();
      return {allowed:a.allowed,durableOperations:a.durableOperations,context:plainScope(scope),eventId:a.eventId,actionId:a.actionId,target:{id:target.id,generation:target.generation},snapshotDigest:a.snapshotDigest};
    });},
    async executeAction(rawCommand,rawScope,call={}){return execute(state,call,async operation=>{
      const scope=readActionScope(rawScope,projectId),command=actionCommand(rawCommand,scope),before=await readEndpoint(operation,'context',base(operation));sameActionScope(scope,before.context);
      const after=await readEndpoint(operation,'action-execute',{...base(operation),sessionId:before.context.sessionId,...actionInput(command),
        fingerprint:command.fingerprint,identityVersion:String(scope.identityVersion)});sameGeneration(before.context,after.context);sameActionScope(scope,after.context);
      const ack=sdpHostRecord(after.data.acknowledgment,['status']);if(!['accepted','denied'].includes(ack.status))resultError();
      return {status:ack.status};
    });},
    // 소비된 operation 영수증. 원 scope 를 그대로 대조하고, 현재 principal 은 subject·project 만 같아야 한다.
    async readActionReceipt(rawInput,rawScope,call={}){return execute(state,call,async operation=>{
      const input=sdpHostRecord(rawInput,['requestId']);if(!match(UUID,input.requestId))resultError();
      const scope=readActionScope(rawScope,projectId),before=await readEndpoint(operation,'context',base(operation));samePrincipal(scope,before.context);
      const after=await readEndpoint(operation,'action-result',{...base(operation),sessionId:before.context.sessionId,requestId:input.requestId});sameGeneration(before.context,after.context);samePrincipal(scope,after.context);
      return actionReceipt(after.data.result,input,scope);
    });},
    readActionResult(input,scope,call={}){return api.readActionReceipt(input,scope,call);},
    // c1(#968) 자기 기기 철회 뒤 본인 영수증. 이 기기는 이미 철회돼 일반 relay·현재 SDP context 를 쓸 수 없다.
    // 1) 영수증 전용 SDP listener 에 같은 기기 인증서로 begin → challenge·서명 대응표 nativeProjectId
    // 2) genuine native host 가 자기 native project 를 대조한 뒤 같은 login closure 로 gateway 에서 1회 ticket
    // 3) finish 로 상환 → 원 operation 의 과거 9필드 scope 영수증. scope 는 저장된 행의 scope 와 같아야 한다(현재 SDP 권한이 아님).
    // nativeHost 는 서버 host 가 만든 native host context 만 받는다(학생 입력 아님).
    async readOwnRevokedReceipt(rawInput,rawScope,call={},nativeHost){
      if(!isNativeHostContext(nativeHost))throw sdpHostError('ENGINE_NOT_CONNECTED');
      return execute(state,call,async operation=>{
        const input=sdpHostRecord(rawInput,['requestId']);if(!match(UUID,input.requestId))resultError();
        const scope=readActionScope(rawScope,projectId);if(!sdpHostReceiptEnabled(operation.snapshot))throw sdpHostError('ENGINE_NOT_CONNECTED');
        operation.assertAlive();verifySdpHostCredentials(operation.snapshot);
        const signal=operation.controller.signal;
        const begun=sdpHostRecord(await postSdpHostOwnReceipt(operation.snapshot,'begin',{requestId:input.requestId},{signal}),['challengeId','contextDigest','expiresAtMs','nativeProjectId']);
        operation.assertAlive();const at=Date.now();
        if(!match(UUID,begun.challengeId)||!match(HASH64,begun.contextDigest)||!positiveMs(begun.expiresAtMs)||begun.expiresAtMs<=at||begun.expiresAtMs>at+10500
          ||typeof begun.nativeProjectId!=='string'||!begun.nativeProjectId||begun.nativeProjectId.length>200)resultError();
        let nativeOperation=null;
        try{
          nativeOperation=await openNativeHostOperation(nativeHost,{signal,timeoutMs:Math.max(1,begun.expiresAtMs-Date.now())});operation.assertAlive();
          const issued=await issueNativeHostReceipt(nativeHost,nativeOperation,{challengeId:begun.challengeId,contextDigest:begun.contextDigest,nativeProjectId:begun.nativeProjectId});
          operation.assertAlive();
          const finished=sdpHostRecord(await postSdpHostOwnReceipt(operation.snapshot,'finish',{challengeId:begun.challengeId,ticket:issued.ticket},{signal}),['receiptScope','result']);
          operation.assertAlive();
          if(finished.receiptScope!=='own-revoked-device')resultError();
          const receipt=actionReceipt(finished.result,input,scope);if(receipt.actionId!=='device:revoke')resultError();
          assertNativeHostOperation(nativeHost,nativeOperation);
          return receipt;
        }finally{if(nativeOperation)closeNativeHostOperation(nativeOperation);}
      },9500);
    },
    readDevices(scope,call={}){return readObservation(state,'devices',scope,call);},
    readSessions(scope,call={}){return readObservation(state,'sessions',scope,call);},
    close(){if(state.closed)return;state.closed=true;for(const operation of state.operations)operation.cancel();}
  });
  engines.set(api,state);return api;
}

// This capability is owned by the trusted host module, never by the student adapter.
const BINDING_SOURCE=['subjectId','projectId','classId','sessionId','policyRevision','registryDigest','catalogDigest'];
const BINDING_AI=['subjectId','alephUserId','siteId','identityVersion','projectId'];
const BINDING_KEYS=['schema','purpose','appId','audience','requestNonce','bindingId','bindingVersion','bindingDigest','approvalKeyId','source','ai','observedAtMs','validUntilMs'];
const canonicalIncident=value=>Array.isArray(value)?value.map(canonicalIncident):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonicalIncident(value[key])])):value;
const incidentDigest=value=>createHash('sha256').update(JSON.stringify(canonicalIncident(value))).digest('hex');
const bindingAuthority=binding=>Object.fromEntries(BINDING_KEYS.filter(key=>!['requestNonce','observedAtMs','validUntilMs'].includes(key)).map(key=>[key,binding[key]]));
function incidentBinding(raw,operation,context,startedAtMs,receivedAtMs){
  const binding=sdpHostRecord(raw,BINDING_KEYS),source=sdpHostRecord(binding.source,BINDING_SOURCE),ai=sdpHostRecord(binding.ai,BINDING_AI);
  if(binding.schema!=='alekov.sdp.ai-binding.v1'||binding.purpose!=='ai.incident.explain'||binding.appId!=='aleph-on'||binding.audience!=='on-client'
    ||binding.requestNonce!==operation.requestNonce||!match(UUID,binding.bindingId)||!positiveMs(binding.bindingVersion)||!match(SUBJECT,binding.bindingDigest)||!match(SUBJECT,binding.approvalKeyId)
    ||BINDING_SOURCE.some(key=>source[key]!==context[key])||!match(/^sid1-[0-9a-f]{64}$/,ai.subjectId)||!match(UUID,ai.alephUserId)||!match(UUID,ai.projectId)
    ||!match(/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/,ai.siteId)||!positiveMs(ai.identityVersion)
    ||!positiveMs(binding.observedAtMs)||!positiveMs(binding.validUntilMs)||binding.observedAtMs<startedAtMs-CLOCK_SKEW_MS||binding.observedAtMs>receivedAtMs+CLOCK_SKEW_MS
    ||binding.validUntilMs<=binding.observedAtMs||binding.validUntilMs>binding.observedAtMs+10000||binding.validUntilMs>context.validUntilMs)scopeError();
  assertFresh(binding);return Object.freeze({...binding,source,ai});
}
export function isOwnedSdpHostEngine(host){return !!host&&typeof host==='object'&&!types.isProxy(host)&&engines.has(host)&&!engines.get(host).closed;}
function incidentOperation(host,cap){
  const owned=incidentOperations.get(cap);
  if(!isOwnedSdpHostEngine(host)||!owned||owned.host!==host||owned.operation.closed)scopeError();
  owned.operation.assertAlive();return owned;
}
async function refreshIncident(owned,signal){
  const {operation}=owned;if(owned.busy)scopeError();owned.busy=true;
  const cancel=()=>operation.cancel();
  try{
    if(signal?.aborted){cancel();operation.assertAlive();}signal?.addEventListener('abort',cancel,{once:true});
    operation.assertAlive();operation.contexts=[];
    const current=await readEndpoint(operation,'context',base(operation));
    if(owned.generation)sameGeneration(owned.generation,current.context);
    operation.requestNonce=randomUUID();
    const bindingStart=Date.now(),response=await readEndpoint(operation,'ai-binding',{...base(operation),sessionId:current.context.sessionId,requestNonce:operation.requestNonce});
    sameGeneration(current.context,response.context);
    const binding=incidentBinding(response.data.binding,operation,response.context,bindingStart,response.receivedAtMs);
    if(owned.bindingAuthority&&incidentDigest(bindingAuthority(binding))!==owned.bindingAuthority)scopeError();
    const eventsStart=Date.now(),events=await readEndpoint(operation,'events',{...base(operation),sessionId:current.context.sessionId});
    sameGeneration(current.context,events.context);
    const raw=events.data.events;if(!Array.isArray(raw)||raw.length>40)resultError();
    observationCoverage(events.data.coverage,'events',raw,{...operation,startedAtMs:eventsStart},events);
    const scope={subjectId:current.context.subjectId,projectId:current.context.projectId,appId:'aleph-on',audience:'on-client'};
    const event=observationEvents(raw,scope).find(row=>row.id===owned.eventId);if(!event)scopeError();
    const eventHash=incidentDigest(event),evidenceIds=Object.freeze(event.evidence.map(row=>row.id));
    if(owned.eventHash&&(eventHash!==owned.eventHash||JSON.stringify(evidenceIds)!==JSON.stringify(owned.evidenceIds)))scopeError();
    finalCheck(operation,operation.contexts);assertFresh(binding);
    const validUntilMs=Math.min(binding.validUntilMs,...operation.contexts.map(value=>value.validUntilMs));
    owned.generation??=current.context;owned.bindingAuthority??=incidentDigest(bindingAuthority(binding));owned.eventHash??=eventHash;owned.evidenceIds??=evidenceIds;
    owned.current=Object.freeze({binding,event,eventHash,evidenceIds,validUntilMs});return owned.current;
  }catch(error){operation.cancel();throw error;}
  finally{signal?.removeEventListener('abort',cancel);owned.busy=false;}
}
export async function openSdpIncidentOperation(host,rawInput,call={}){
  if(!isOwnedSdpHostEngine(host))scopeError();
  const {eventId}=sdpHostRecord(rawInput,['eventId']),options=sdpHostRecord(call,[],['signal','timeoutMs']);
  const signal=sdpHostSignal(options.signal),timeoutMs=options.timeoutMs??TIMEOUT_MS;
  if(!match(ID,eventId)||!Number.isSafeInteger(timeoutMs)||timeoutMs<=0||timeoutMs>120000)resultError();
  const operation=makeOperation(engines.get(host),{signal},timeoutMs),cap=Object.freeze(Object.create(null));
  operation.privateIncident=true;operation.requestNonce=randomUUID();
  const owned={host,operation,eventId,busy:false,current:null,generation:null,bindingAuthority:null,eventHash:null,evidenceIds:null};incidentOperations.set(cap,owned);
  try{await refreshIncident(owned,signal);assertSdpIncidentOperation(host,cap);return cap;}
  catch(error){closeSdpIncidentOperation(cap);throw error;}
}
export async function readSdpIncidentOperation(host,cap,call={}){
  const options=sdpHostRecord(call,[],['signal']),signal=sdpHostSignal(options.signal),owned=incidentOperation(host,cap);
  await refreshIncident(owned,signal);return assertSdpIncidentOperation(host,cap);
}
export function assertSdpIncidentOperation(host,cap){
  const owned=incidentOperation(host,cap);if(owned.busy||!owned.current)scopeError();
  finalCheck(owned.operation,owned.operation.contexts);assertFresh(owned.current.binding);assertFresh(owned.current);return owned.current;
}
export function closeSdpIncidentOperation(cap){const owned=incidentOperations.get(cap);if(!owned)return;incidentOperations.delete(cap);owned.operation.close();}
